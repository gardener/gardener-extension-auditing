// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shoot_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tf "github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
)

var _ = Describe("Auditing Extension Tests", Label("Auditing"), func() {
	f := defaultShootCreationFramework()
	f.Shoot = defaultShoot("e2e-default")

	It("Create Shoot, Enable Auditing Extension, Delete Shoot", Label("good-case"), func() {
		By("Create Shoot")
		ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.CreateShootAndWaitForCreation(ctx, false)).To(Succeed())
		f.Verify()

		Expect(ensureAuditlogPolicy(ctx, f.GardenClient.Client())).To(Succeed())

		By("Enable Auditing Extension")
		_, seedClient, err := f.GetSeed(ctx, *f.Shoot.Status.SeedName)
		Expect(err).NotTo(HaveOccurred())
		project, err := f.GetShootProject(ctx, f.Shoot.Namespace)
		Expect(err).NotTo(HaveOccurred())
		shootSeedNamespace := tf.ComputeTechnicalID(project.Name, f.Shoot)

		Expect(ensureNetworkPolicy(ctx, seedClient.Client(), shootSeedNamespace)).To(Succeed())

		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.UpdateShoot(ctx, f.Shoot, ensureAuditingExtensionIsEnabled)).To(Succeed())

		depl, err := getAuditlogForwarderDeployment(ctx, seedClient.Client(), shootSeedNamespace)
		Expect(err).NotTo(HaveOccurred())
		one := int32(1)
		Expect(*depl.Spec.Replicas).To(BeNumerically(">=", one))
		Expect(depl.Status.ReadyReplicas).To(BeNumerically(">=", one))

		By("Produce an audit event")
		testServiceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name:      "test-serviceaccount",
			Namespace: "default",
		}}
		Expect(f.ShootFramework.ShootClient.Client().Create(ctx, testServiceAccount)).To(Succeed())

		By("Check if the audit event is forwarded")
		Eventually(func() error {
			podList := &corev1.PodList{}
			podLabelSelector := client.MatchingLabels{
				"app.kubernetes.io/name":    "auditlog-forwarder",
				"app.kubernetes.io/part-of": "auditing",
			}
			if err := seedClient.Client().List(ctx, podList, client.InNamespace(shootSeedNamespace), podLabelSelector); err != nil {
				return err
			}
			if len(podList.Items) == 0 {
				return errors.New("expected at least one auditlog-forwarder pod")
			}

			count := 0
			expectedMessage := "Forwarded audit events to all outputs"
			for _, pod := range podList.Items {
				By("Checking logs of auditlog-forwarder pod " + pod.Name)
				podLogOpts := &corev1.PodLogOptions{
					Container: "auditlog-forwarder",
				}

				logs, err := kubernetesutils.GetPodLogs(ctx, seedClient.Kubernetes().CoreV1().Pods(shootSeedNamespace), pod.Name, podLogOpts)
				if err != nil {
					return err
				}

				scanner := bufio.NewScanner(bytes.NewReader(logs))

				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, expectedMessage) {
						count++
					}
				}
				if err := scanner.Err(); err != nil {
					return err
				}
			}
			if count == 0 {
				return fmt.Errorf("expected at least one line containing '%s', but found %d", expectedMessage, count)
			}
			return nil
		}).WithTimeout(1 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())

		By("Delete Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.DeleteShootAndWaitForDeletion(ctx, f.Shoot)).To(Succeed())
	})
})
