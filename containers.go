package proxmox

import (
	"fmt"
)

func (c *Container) Delete() (status string, err error) {
	return status, c.client.Delete(fmt.Sprintf("/nodes/%s/lxc/%d", c.Node, c.VMID), &status)
}

func (c *Container) Start() (status string, err error) {
	return status, c.client.Post(fmt.Sprintf("/nodes/%s/lxc/%d/status/start", c.Node, c.VMID), nil, &status)
}

func (c *Container) Stop() (status *ContainerStatus, err error) {
	return status, c.client.Post(fmt.Sprintf("/nodes/%s/lxc/%d/status/stop", c.Node, c.VMID), nil, &status)
}

func (c *Container) Suspend() (status *ContainerStatus, err error) {
	return status, c.client.Post(fmt.Sprintf("/nodes/%s/lxc/%d/status/suspend", c.Node, c.VMID), nil, &status)
}

func (c *Container) Reboot() (status *ContainerStatus, err error) {
	return status, c.client.Post(fmt.Sprintf("/nodes/%s/lxc/%d/status/reboot", c.Node, c.VMID), nil, &status)
}

func (c *Container) Resume() (status *ContainerStatus, err error) {
	return status, c.client.Post(fmt.Sprintf("/nodes/%s/lxc/%d/status/resume", c.Node, c.VMID), nil, &status)
}
