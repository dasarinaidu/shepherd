package features

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/shepherd/clients/rancher"
	v1 "github.com/rancher/shepherd/clients/rancher/v1"
)

const (
	ManagementFeature = "management.cattle.io.feature"
)

// IsFeatureEnabled returns true when the named Rancher feature flag has Spec.Value == true.
// Uses the Steve client, matching the existing UpdateFeatureFlag helper.
func IsFeatureEnabled(client *rancher.Client, name string) (bool, error) {
	flagObj, err := client.Steve.SteveType(ManagementFeature).ByID(name)
	if err != nil {
		return false, err
	}
	feature := &v3.Feature{}
	if err := v1.ConvertToK8sType(flagObj.JSONResp, feature); err != nil {
		return false, err
	}
	if feature.Spec.Value == nil {
		return false, nil
	}
	return *feature.Spec.Value, nil
}
