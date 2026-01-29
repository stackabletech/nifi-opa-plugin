### How to create a release

Open a PR to bump the `project.version` in `authorizer/pom.xml`, you can name it something like `chore: Release x.x.x`.

The Git tag as well as the GitHub release is automatically created by CI after merge.
Don't create them yourself, as the CI will attach a pre-build NAR file.
