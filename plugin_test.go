package main

import (
	"testing"

	"github.com/gotify/plugin-api"
	"github.com/stretchr/testify/assert"
)

func TestAPICompatibility(t *testing.T) {
	assert.Implements(t, (*plugin.Plugin)(nil), new(ArchSec))
	assert.Implements(t, (*plugin.Storager)(nil), new(ArchSec))
	assert.Implements(t, (*plugin.Configurer)(nil), new(ArchSec))
	assert.Implements(t, (*plugin.Messenger)(nil), new(ArchSec))
}
