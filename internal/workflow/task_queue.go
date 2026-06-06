package workflow

import "fmt"

const ArtifactTaskQueuePrefix = "weave-artifact"

func ArtifactTaskQueue(artifactName string) string {
	if artifactName == "" {
		return ArtifactTaskQueuePrefix
	}
	return fmt.Sprintf("%s-%s", ArtifactTaskQueuePrefix, artifactName)
}
