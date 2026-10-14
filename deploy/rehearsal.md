# The genesis dress rehearsal

Genesis is rehearsed end to end before it is run, with the real custodians and signers, the TDX
hosts the nodes will run on, and test keys only. After genesis it is repeated every quarter on a
separate cluster.

## Test keys and a rehearsal build

- **Test release keys.** Each signer makes one as in [`signer-keys.md`](signer-keys.md), with
  `TEST` in the file name. A branch off `main` replaces `prod.pub` with their three lines and is
  never merged. A tag `v<next version>-rehearsal.<n>` on it runs the release: its images and its
  KMS init-data accept only documents signed by the test keys, and no production document lists
  their Revision.
- **Test custodian keys.** Each custodian runs `alpha keygen --custodian --out TEST-custodian.key`
  with the production `alpha` built at the rehearsal tag in the pinned image and compared, as in
  [`signer-keys.md`](signer-keys.md), and sends the public key. These are not the keys they
  bring to genesis.
- **A rehearsal document URL**, served like the production one but never the production URL. It
  is one of the repository variables the release measures, so it is set before the rehearsal tag
  and set back to the production URL as soon as that tag's `render` job has finished.

## The run

Time every step and write down what went wrong.

1. **Verify the release** as in [`verify-release.md`](verify-release.md).
2. **Sign** the document with two test keys and the `alpha` built at the rehearsal tag, as in
   [Signing the Revision](kata/README.md#signing-the-revision), and publish it once
   `alpha sign --check` accepts it.
3. **Genesis.** [Day 0](kata/README.md#day-0), steps 1 to 9, with the test custodians' public
   keys and test keys for every signature. Then [Verify](kata/README.md#verify).
4. **Lose every node.**

   ```sh
   kubectl -n alpha-kms delete pod kms-0 kms-1
   kubectl -n alpha-kms wait --for=create pod/kms-0 --timeout=10m
   kubectl -n alpha-kms wait --for=jsonpath='{.status.phase}'=Running pod/kms-0 --timeout=10m
   kubectl -n alpha-kms port-forward pod/kms-0 8443:8443 &
   sleep 2; curl -sk -w ' %{http_code}\n' https://localhost:8443/ready   # {"sealed":true} 503
   ```
5. **Unseal with two shares**, one custodian inside the company at the port-forward and one
   outside it, remotely, as in [All nodes lost](kata/README.md#restart-upgrade-loss). The
   operator gives the remote custodian a tunnel to the port-forward, for example an SSH local
   forward. The tunnel is not trusted: their `alpha unseal` appraises the node's evidence and pins
   the attested key itself. One share leaves the node sealed; the second unseals it,
   `kms-1` joins and `kubectl -n alpha-kms get statefulset kms` shows `2/2`.
6. **A lost share.** Steps 4 and 5 again with the share not used yet and one of the other two,
   so all three shares unseal at least once.

## Passes when

Every step above succeeds without a change to the files in `deploy/`, each custodian unsealed
with the `alpha` whose SHA-256 is in their record, and the times show both nodes lost to both
serving within a working day. Any fix found is a pull request before genesis, and the rehearsal
runs again if it changes the release.

## Afterwards

Delete both namespaces and the trust-db volume, the rehearsal branch, and every test key and
share on every machine and drive. The rehearsal images stay at their tag. The record keeps the
times, the SHA-256s and the problems, and no secret.
