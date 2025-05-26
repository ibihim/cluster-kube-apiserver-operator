package auth

import (
	"fmt"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type FeatureGateLister interface {
	FeatureGateAccessor() featuregates.FeatureGateAccess
}

var configPath = []string{"admission", "pluginConfig", "PodSecurity", "configuration", "defaults"}

// We want this:
/*
	admission:
		pluginConfig:
			PodSecurity:
				configuration:
					kind: PodSecurityConfiguration
					apiVersion: pod-security.admission.config.k8s.io/v1
					defaults:
						enforce: "restricted"
						enforce-version: "latest"
*/
func SetPodSecurityAdmissionToEnforceRestricted(config map[string]interface{}) error {
	psaEnforceRestricted := map[string]interface{}{
		"enforce":         "privileged",
		"enforce-version": "latest",
		"audit":           "restricted",
		"audit-version":   "latest",
		"warn":            "restricted",
		"warn-version":    "latest",
	}

	unstructured.RemoveNestedField(config, configPath...)
	if err := unstructured.SetNestedMap(config, psaEnforceRestricted, configPath...); err != nil {
		return fmt.Errorf("failed to set PodSecurity to enforce restricted: %w", err)
	}

	return nil
}

func SetPodSecurityAdmissionToEnforcePrivileged(config map[string]interface{}) error {
	psaEnforceRestricted := map[string]interface{}{
		"enforce":         "privileged",
		"enforce-version": "latest",
		"audit":           "restricted",
		"audit-version":   "latest",
		"warn":            "restricted",
		"warn-version":    "latest",
	}

	unstructured.RemoveNestedField(config, configPath...)
	if err := unstructured.SetNestedMap(config, psaEnforceRestricted, configPath...); err != nil {
		return fmt.Errorf("failed to set PodSecurity to enforce restricted: %w", err)
	}

	return nil
}

func NewObservePodSecurityAdmissionEnforcementFunc(featureGateAccessor featuregates.FeatureGateAccess) configobserver.ObserveConfigFunc {
	return (&psaEnforcement{
		featureGateAccessor: featureGateAccessor,
	}).ObservePodSecurityAdmissionEnforcement
}

type psaEnforcement struct {
	featureGateAccessor featuregates.FeatureGateAccess
}

// ObserveFeatureFlags fills in --feature-flags for the kube-apiserver
func (o *psaEnforcement) ObservePodSecurityAdmissionEnforcement(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	return observePodSecurityAdmissionEnforcement(o.featureGateAccessor, recorder, existingConfig)
}

func observePodSecurityAdmissionEnforcement(featureGateAccessor featuregates.FeatureGateAccess, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, configPath)
	}()

	errs := []error{}

	if !featureGateAccessor.AreInitialFeatureGatesObserved() {
		// if we haven't observed featuregates yet, return the existing
		return existingConfig, nil
	}

	observedConfig := map[string]interface{}{}
	if err := SetPodSecurityAdmissionToEnforcePrivileged(observedConfig); err != nil {
		return existingConfig, append(errs, err)
	}

	return observedConfig, errs
}
