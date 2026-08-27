// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

//go:generate sh -c "$TOOLS_BIN_DIR/extension-generator --name=extension-auditing --component-category=extension --provider-type=auditing --extension-oci-repository=europe-docker.pkg.dev/gardener-project/public/charts/gardener/extensions/auditing:$(cat ../VERSION) --admission-runtime-oci-repository=europe-docker.pkg.dev/gardener-project/public/charts/gardener/extensions/auditing-admission-runtime:$(cat ../VERSION) --admission-application-oci-repository=europe-docker.pkg.dev/gardener-project/public/charts/gardener/extensions/auditing-admission-application:$(cat ../VERSION) --destination=./extension/base/extension.yaml"
//go:generate sh -c "$TOOLS_BIN_DIR/kustomize build ./extension -o ./extension.yaml"

package example
