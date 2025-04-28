/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pleg

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/component-base/metrics/testutil"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	critest "k8s.io/cri-api/pkg/apis/testing"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	containertest "k8s.io/kubernetes/pkg/kubelet/container/testing"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	testingclock "k8s.io/utils/clock/testing"
)

func newTestEventedPLEG() *EventedPLEG {
	return &EventedPLEG{
		runtime:        &containertest.FakeRuntime{},
		clock:          testingclock.NewFakeClock(time.Time{}),
		cache:          kubecontainer.NewCache(),
		runtimeService: critest.NewFakeRuntimeService(),
		eventChannel:   make(chan *PodLifecycleEvent, 100),
	}
}

func TestHealthyEventedPLEG(t *testing.T) {
	metrics.Register()
	pleg := newTestEventedPLEG()

	_, _, events := createTestPodsStatusesAndEvents(100)
	for _, event := range events[:5] {
		pleg.eventChannel <- event
	}

	// test if healthy when event channel has 5 events
	isHealthy, err := pleg.Healthy()
	require.NoError(t, err)
	assert.True(t, isHealthy)

	// send remaining 95 events and make channel out of capacity
	for _, event := range events[5:] {
		pleg.eventChannel <- event
	}
	// pleg is unhealthy when channel is out of capacity
	isHealthy, err = pleg.Healthy()
	require.Error(t, err)
	assert.False(t, isHealthy)
}

func TestUpdateRunningPodMetric(t *testing.T) {
	metrics.Register()
	pleg := newTestEventedPLEG()

	podStatuses := make([]*kubecontainer.PodStatus, 5)
	for i := range podStatuses {
		id := fmt.Sprintf("test-pod-%d", i)
		podStatuses[i] = &kubecontainer.PodStatus{
			ID: types.UID(id),
			SandboxStatuses: []*v1.PodSandboxStatus{
				{Id: id},
			},
			ContainerStatuses: []*kubecontainer.Status{
				{ID: kubecontainer.ContainerID{ID: id}, State: kubecontainer.ContainerStateRunning},
			},
		}

		pleg.updateRunningPodMetric(podStatuses[i])
		pleg.cache.Set(podStatuses[i].ID, podStatuses[i], nil, time.Now())

	}
	pleg.cache.UpdateTime(time.Now())

	expectedMetric := `
# HELP kubelet_running_pods [ALPHA] Number of pods that have a running pod sandbox
# TYPE kubelet_running_pods gauge
kubelet_running_pods 5
`
	testMetric(t, expectedMetric, metrics.RunningPodCount.FQName())

	// stop sandbox containers for first 2 pods
	for _, podStatus := range podStatuses[:2] {
		podId := string(podStatus.ID)
		newPodStatus := kubecontainer.PodStatus{
			ID: podStatus.ID,
			SandboxStatuses: []*v1.PodSandboxStatus{
				{Id: podId},
			},
			ContainerStatuses: []*kubecontainer.Status{
				// update state to container exited
				{ID: kubecontainer.ContainerID{ID: podId}, State: kubecontainer.ContainerStateExited},
			},
		}

		pleg.updateRunningPodMetric(&newPodStatus)
		pleg.cache.Set(newPodStatus.ID, &newPodStatus, nil, time.Now())
	}
	pleg.cache.UpdateTime(time.Now())

	expectedMetric = `
# HELP kubelet_running_pods [ALPHA] Number of pods that have a running pod sandbox
# TYPE kubelet_running_pods gauge
kubelet_running_pods 3
`
	testMetric(t, expectedMetric, metrics.RunningPodCount.FQName())
}

func testMetric(t *testing.T, expectedMetric string, metricName string) {
	err := testutil.GatherAndCompare(metrics.GetGather(), strings.NewReader(expectedMetric), metricName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEventedPLEG_getPodIPs(t *testing.T) {
	cache := kubecontainer.NewCache()
	type args struct {
		pid    types.UID
		status *kubecontainer.PodStatus
	}
	tests := []struct {
		name      string
		args      args
		oldstatus *kubecontainer.PodStatus
		expected  []string
	}{
		{
			name: "status ips is not empty",
			args: args{
				pid: "62212",
				status: &kubecontainer.PodStatus{
					IPs: []string{"10.0.0.10", "10.23.0.1"},
				},
			},
			oldstatus: &kubecontainer.PodStatus{
				IPs: []string{"192.168.0.10", "192.168.0.1"},
			},
			expected: []string{"10.0.0.10", "10.23.0.1"},
		},
		{
			name: "status ips is empty and SandboxStatuses has PodSandboxState_SANDBOX_READY state",
			args: args{
				pid: "62212",
				status: &kubecontainer.PodStatus{
					SandboxStatuses: []*v1.PodSandboxStatus{
						{
							Id:       "sandboxID2",
							Metadata: &v1.PodSandboxMetadata{Attempt: uint32(1)},
							State:    v1.PodSandboxState_SANDBOX_READY,
						},
						{
							Id:       "sandboxID1",
							Metadata: &v1.PodSandboxMetadata{Attempt: uint32(0)},
							State:    v1.PodSandboxState_SANDBOX_NOTREADY,
						},
					},
				},
			},
			oldstatus: &kubecontainer.PodStatus{
				IPs: []string{"192.168.0.10", "192.168.0.1"},
			},
			expected: nil,
		},
		{
			name: "status and cache ips are empty",
			args: args{
				pid:    "62212",
				status: &kubecontainer.PodStatus{},
			},
			oldstatus: &kubecontainer.PodStatus{
				IPs: []string{},
			},
			expected: nil,
		},
		{
			name: "sandbox state is no PodSandboxState_SANDBOX_READY",
			args: args{
				pid: "62212",
				status: &kubecontainer.PodStatus{
					SandboxStatuses: []*v1.PodSandboxStatus{
						{
							Id:       "sandboxID2",
							Metadata: &v1.PodSandboxMetadata{Attempt: uint32(1)},
							State:    v1.PodSandboxState_SANDBOX_NOTREADY,
						},
						{
							Id:       "sandboxID1",
							Metadata: &v1.PodSandboxMetadata{Attempt: uint32(0)},
							State:    v1.PodSandboxState_SANDBOX_NOTREADY,
						},
					},
				},
			},
			oldstatus: &kubecontainer.PodStatus{
				IPs: []string{"192.168.0.10", "192.168.0.1"},
			},
			expected: []string{"192.168.0.10", "192.168.0.1"},
		},
	}
	for _, test := range tests {
		cache.Set(test.args.pid, test.oldstatus, nil, time.Time{})
		e := &EventedPLEG{
			cache: cache,
		}
		t.Run(test.name, func(t *testing.T) {
			if got := e.getPodIPs(test.args.pid, test.args.status); !reflect.DeepEqual(got, test.expected) {
				t.Errorf("EventedPLEG.getPodIPs() = %v, expected %v", got, test.expected)
			}
		})
	}
}

func TestEventedPLEGUsage(t *testing.T) {
	// init status false
	assert.False(t, isEventedPLEGInUse(), "Expected EventedPLEG not in use initially")

	// set status true
	setEventedPLEGUsage(true)
	assert.True(t, isEventedPLEGInUse(), "Expected EventedPLEG to be in use after enabling")

	// set status false
	setEventedPLEGUsage(false)
	assert.False(t, isEventedPLEGInUse(), "Expected EventedPLEG not in use after disabling")
}

func TestSendPodLifecycleEvent(t *testing.T) {
	eventChannel := make(chan *PodLifecycleEvent, 3)
	eventedPLEG := &EventedPLEG{
		eventChannel: eventChannel,
	}

	// send events to channel
	for i := 0; i < 3; i++ {
		eventedPLEG.sendPodLifecycleEvent(&PodLifecycleEvent{ID: types.UID("pod-" + strconv.Itoa(i))})
	}

	eventedPLEG.sendPodLifecycleEvent(&PodLifecycleEvent{ID: "pod-overflow"})

	// check channel events
	assert.Len(t, eventChannel, 3, "Event channel should contain 3 events")
}

func TestUpdateGlobalCache(t *testing.T) {
	// Create a fake cache
	fakeCache := kubecontainer.NewCache()
	eventedPLEG := &EventedPLEG{
		cache: fakeCache,
	}

	// Define test cases
	testCases := []struct {
		name        string
		initialTime time.Time
	}{
		{
			name:        "Initial time is one hour ago",
			initialTime: time.Now().Add(-1 * time.Hour),
		},
		{
			name:        "Initial time is one day ago",
			initialTime: time.Now().Add(-24 * time.Hour),
		},
	}

	// Iterate over the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set the initial time in the fake cache
			podUID := types.UID("test-pod")
			fakeCache.UpdateTime(tc.initialTime)
			fakeCache.Set(podUID, &kubecontainer.PodStatus{}, nil, tc.initialTime)

			// Call updateGlobalCache
			eventedPLEG.updateGlobalCache()

			// Use GetNewerThan to validate that the cache time was updated
			_, err := fakeCache.GetNewerThan(podUID, tc.initialTime)
			if err != nil {
				t.Errorf("Expected cache to be updated, but it was not. Initial time: %v", tc.initialTime)
			}
		})
	}
}
