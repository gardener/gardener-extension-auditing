// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package secret_test

import (
	testing "testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSecretValidator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Secret Validator Suite")
}
