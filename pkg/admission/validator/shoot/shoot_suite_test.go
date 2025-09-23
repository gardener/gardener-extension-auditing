// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	testing "testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestShootValidator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shoot Validator Suite")
}
