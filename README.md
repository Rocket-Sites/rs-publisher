# rs-publisher

The reusable GitHub Actions workflow that publishes a Rocket Site, plus the
composite actions it orchestrates. That is the whole of this repository:
36 files, of which 35 are the publisher
under `.github/` and this README is the last one.

Every client site repository calls it like this, pinned to the moving major tag
and never to a branch:

```yaml
jobs:
  deploy:
    uses: Rocket-Sites/rs-publisher/.github/workflows/deploy-site.yml@v1
```

The header of `.github/workflows/deploy-site.yml` carries the full usage
example, including the inputs and the two secrets a caller maps by name.

## This repository is generated

It is a distribution point, not a place to work. The publisher is authored in a
separate private repository and materialised here on release, so an edit made
here would be overwritten by the next one. **Issues and pull requests belong
upstream.** If you are an agency running a Rocket Site and something in a deploy
looks wrong, report it through the channel you were onboarded with.

This page is generated with the rest of it. Nothing in this repository is
written by hand, including the sentence you are reading and the file counts
above.

Each release is a commit with no parent, carrying only the released tree. There
is no history here to read, deliberately: this repository is public and the
repository the publisher is authored in is not.

## Tags

- `v1` is the moving major tag. It is force-moved to each release, and it is
  what every caller should pin.
- `v1.N.N` are immutable. They are the record of where `v1` was moved to,
  and they are protected against deletion and update.

You can check the pair yourself, and you do not need any credentials to do it:

```bash
git ls-remote https://github.com/Rocket-Sites/rs-publisher refs/tags/v1 'refs/tags/v1.*'
```

`v1` should resolve to the same commit as the highest `v1.N.N`. If it does
not, the moving tag was moved somewhere other than the release it was cut from.
