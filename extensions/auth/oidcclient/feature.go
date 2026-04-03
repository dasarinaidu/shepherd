package oidcclient

import (
	"context"
	"fmt"

	"github.com/rancher/shepherd/clients/rancher"
	oidcauth "github.com/rancher/shepherd/clients/rancher/auth/oidc"
	"github.com/rancher/shepherd/extensions/defaults"
	"github.com/rancher/shepherd/extensions/features"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	// RancherDeploymentName is the deployment name of the Rancher server pod.
	RancherDeploymentName = "rancher"
	// RancherDeploymentNamespace is the namespace where the Rancher server runs.
	RancherDeploymentNamespace = "cattle-system"
)

// EnableOIDCFeatureFlag enables the oidc-provider feature flag if not already enabled,
// waits for the Rancher pod to restart and become ready, and registers DisableOIDCFeatureFlag
// as a session cleanup function so the flag is reverted when the test session ends.
//
// Enabling oidc-provider triggers an automatic Rancher pod restart as a side effect; the
// OIDC provider only initializes after the pod comes back up. Calls to OIDC endpoints made
// before this function returns may fail.
func EnableOIDCFeatureFlag(client *rancher.Client) error {
	enabled, err := features.IsFeatureEnabled(client, oidcauth.OIDCProviderFeatureFlag)
	if err != nil {
		return fmt.Errorf("checking oidc-provider feature flag state: %w", err)
	}
	if enabled {
		logrus.Info("[OIDC setup] oidc-provider feature flag is already enabled — skipping restart")
		return nil
	}

	logrus.Info("[OIDC setup] Enabling oidc-provider feature flag — Rancher will restart")
	client.Session.RegisterCleanupFunc(func() error {
		return DisableOIDCFeatureFlag(client)
	})

	flagObj, err := client.Steve.SteveType(features.ManagementFeature).ByID(oidcauth.OIDCProviderFeatureFlag)
	if err != nil {
		return fmt.Errorf("fetching oidc-provider feature flag: %w", err)
	}
	if _, err := features.UpdateFeatureFlag(client.Steve, flagObj, true); err != nil {
		return fmt.Errorf("enabling oidc-provider feature flag: %w", err)
	}

	return waitForRancherReady(client)
}

// DisableOIDCFeatureFlag disables the oidc-provider feature flag. Disabling does not
// trigger a Rancher pod restart so no readiness wait is needed.
func DisableOIDCFeatureFlag(client *rancher.Client) error {
	logrus.Info("[OIDC teardown] Disabling oidc-provider feature flag")
	flagObj, err := client.Steve.SteveType(features.ManagementFeature).ByID(oidcauth.OIDCProviderFeatureFlag)
	if err != nil {
		return fmt.Errorf("fetching oidc-provider feature flag: %w", err)
	}
	if _, err := features.UpdateFeatureFlag(client.Steve, flagObj, false); err != nil {
		return fmt.Errorf("disabling oidc-provider feature flag: %w", err)
	}
	return nil
}

// waitForRancherReady polls the Rancher deployment directly via the k8s API
// (bypassing the Rancher proxy) until all replicas are updated, ready, and available.
// This is used immediately after toggling oidc-provider, since the proxy is unavailable
// during the restart.
func waitForRancherReady(client *rancher.Client) error {
	logrus.Info("[OIDC setup] Waiting for Rancher to be fully ready (max 5m)")
	k8sClient, err := kubernetes.NewForConfig(client.WranglerContext.RESTConfig)
	if err != nil {
		return fmt.Errorf("building k8s client for Rancher readiness check: %w", err)
	}
	return kwait.PollUntilContextTimeout(
		context.Background(), defaults.TenSecondTimeout, defaults.FiveMinuteTimeout, false,
		func(ctx context.Context) (bool, error) {
			d, getErr := k8sClient.AppsV1().Deployments(RancherDeploymentNamespace).
				Get(ctx, RancherDeploymentName, metav1.GetOptions{})
			if getErr != nil {
				logrus.Debugf("[OIDC] Rancher not yet readable: %v", getErr)
				return false, nil
			}
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			if d.Status.UpdatedReplicas >= desired &&
				d.Status.ReadyReplicas >= desired &&
				d.Status.AvailableReplicas >= desired &&
				d.Status.Replicas == desired {
				logrus.Info("[OIDC setup] Rancher is stable — all replicas ready")
				return true, nil
			}
			return false, nil
		},
	)
}
