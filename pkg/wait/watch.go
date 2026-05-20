package wait

import (
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	TimeoutError         = "timeout waiting on condition"
	WatchConnectionError = "error with watch connection"
)

// WatchCheckFunc is the function type of `check` needed for WatchWait e.g.
//
//	 checkFunc := func(event watch.Event) (ready bool, err error) {
//			cluster := event.Object.(*apisV1.Cluster)
//			ready = cluster.Status.Ready
//			return ready, nil
//	 }
type WatchCheckFunc func(watch.Event) (bool, error)

// WatchWait uses the `watchInterface`  to wait until the `check` function to returns true.
// e.g. WatchWait for provisioning a cluster
//
//	 result, err := r.client.Provisioning.Clusters(namespace).Watch(context.TODO(), metav1.ListOptions{
//			FieldSelector:  "metadata.name=" + clusterName,
//			TimeoutSeconds: &defaults.WatchTimeoutSeconds,
//	 })
//	 require.NoError(r.T(), err)
//	 err = wait.WatchWait(result, checkFunc)
func WatchWait(watchInterface watch.Interface, check WatchCheckFunc) error {
	defer func() {
		watchInterface.Stop()
	}()

	for {
		select {
		case event, open := <-watchInterface.ResultChan():
			if event.Type == watch.Error {
				if status, ok := event.Object.(*metav1.Status); ok {
					return fmt.Errorf("%s: %s (reason=%s code=%d)", WatchConnectionError, status.Message, status.Reason, status.Code)
				}
				return fmt.Errorf("%s: unexpected event.Object type %T: %+v", WatchConnectionError, event.Object, event.Object)
			}
			if !open {
				return errors.New(TimeoutError)
			}

			done, err := check(event)
			if err != nil {
				return err
			}

			if done {
				return nil
			}
		}
	}
}
