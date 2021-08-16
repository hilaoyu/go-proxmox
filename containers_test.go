// +build containers

package proxmox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStartContainer(t *testing.T) {

	n := NewContainer{
		Node:       td.nodeName,
		VMID:       110,
		OSTemplate: "alpine-3.14-default_20210623_amd64.tar.xz",
		Storage:    "local-lvm",
	}
	_, err := td.node.NewContainer(n)
	assert.Nil(t, err)
	container, err := td.node.Container(n.VMID)
	assert.Nil(t, err)
	assert.Equal(t, "stopped", container.Status)

	_, err = container.Start()
	assert.Nil(t, err)

	run, err := td.node.Container(n.VMID)
	assert.Nil(t, err)
	assert.Equal(t, "running", run.Status)

	stop, err := td.node.Container(n.VMID)
	assert.Nil(t, err)
	assert.Equal(t, "stopped", stop.Status)

	delete, err := td.node.Container(n.VMID)
	assert.Nil(t, err)
	assert.Equal(t, "deleted", delete.Status)
}
