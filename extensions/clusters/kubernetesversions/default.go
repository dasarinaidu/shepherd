package kubernetesversions

import (
	"fmt"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/sirupsen/logrus"
)

// Default is a helper function that returns the latest version if kubernetes version of a specific cluster type
func Default(client *rancher.Client, provider string, kubernetesVersions []string) ([]string, error) {

	switch {
	case provider == clusters.RKE1ClusterType.String():
		defaultVersionData, err := client.Management.Setting.ByID("k8s-version")

		if err != nil {
			return nil, err
		}

		defaultVersion := defaultVersionData.Value

		if kubernetesVersions == nil {
			kubernetesVersions = append(kubernetesVersions, defaultVersion)
			logrus.Infof("no version found in kubernetesVersions; default rke1 kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		} else if len(kubernetesVersions) == 0 {
			kubernetesVersions = append(kubernetesVersions, defaultVersion)
			logrus.Infof("empty list found in kubernetesVersions; default rke1 kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		} else if kubernetesVersions[0] == "" {
			kubernetesVersions[0] = defaultVersion
			logrus.Infof("empty string value found in kubernetesVersions; default rke1 kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		}

	case provider == clusters.RKE2ClusterType.String():
		defaultVersionData, err := client.Management.Setting.ByID("rke2-default-version")

		if err != nil {
			return nil, err
		}

		defaultVersion := `v` + defaultVersionData.Value

		if kubernetesVersions == nil {
			kubernetesVersions = append(kubernetesVersions, defaultVersion)
			logrus.Infof("no version found in kubernetesVersions; default rke2 kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		} else if len(kubernetesVersions) == 0 {
			kubernetesVersions = append(kubernetesVersions, defaultVersion)
			logrus.Infof("empty list found in kubernetesVersions; default rke2 kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		} else if kubernetesVersions[0] == "" {
			kubernetesVersions[0] = defaultVersion
			logrus.Infof("empty string value found in kubernetesVersions; default rke2 kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		}

	case provider == clusters.K3SClusterType.String():
		defaultVersionData, err := client.Management.Setting.ByID("k3s-default-version")

		if err != nil {
			return nil, err
		}

		defaultVersion := `v` + defaultVersionData.Value

		if kubernetesVersions == nil {
			kubernetesVersions = append(kubernetesVersions, defaultVersion)
			logrus.Infof("no version found in kubernetesVersions; default k3s kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		} else if len(kubernetesVersions) == 0 {
			kubernetesVersions = append(kubernetesVersions, defaultVersion)
			logrus.Infof("empty list found in kubernetesVersions; default k3s kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		} else if kubernetesVersions[0] == "" {
			kubernetesVersions[0] = defaultVersion
			logrus.Infof("empty string value found in kubernetesVersions; default k3s kubernetes version %v will be used: %v", defaultVersion, kubernetesVersions)
		}

	default:
		return nil, fmt.Errorf("invalid provider: %v; valid providers: rke1, rke2, k3s", provider)
	}

	return kubernetesVersions, nil
}
