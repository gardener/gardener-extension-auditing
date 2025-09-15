// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

//go:generate sh -c "bash $GARDENER_HACK_DIR/generate-controller-registration.sh auditing . $(cat ../../VERSION) ../../example/controller-registration.yaml Extension:auditing"
//go:generate sh -c "sed -i 's/ type: auditing/ type: auditing\\n    lifecycle:\\n      reconcile: BeforeKubeAPIServer\\n      delete: AfterKubeAPIServer\\n      migrate: AfterKubeAPIServer/' ../../example/controller-registration.yaml"
//go:generate sh -c "sed -i 's/ type: auditing/ type: auditing\\n    workerlessSupported: true/' ../../example/controller-registration.yaml"

// Package chart enables go:generate support for generating the correct controller registration.
package chart
