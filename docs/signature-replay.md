# Finding : Signature Replay dans SignatureReplayVault

| Champ | Valeur |
|---|---|
| **Sévérité** | High (impact élevé, probabilité élevée) |
| **Catégorie** | Cryptographie / rejeu de signature |
| **Contrat affecté** | `src/vulnerable/SignatureReplayVault.sol`, fonction `withdrawWithSignature()` |
| **Contrat corrigé** | `src/fixed/SignatureReplayVaultFixed.sol` |

## Description
Le vault paie sur présentation d'une signature du `signer`. Le message signé
ne contient que `(to, amount)`. Le contrat ne mémorise pas qu'une signature a
déjà été utilisée : la même signature reste valide indéfiniment.

## Impact
Une signature autorisant 1 ETH peut être resoumise autant de fois qu'il reste
des fonds. Dans le test : 1 seule autorisation de 1 ETH, 5 retraits, vault vidé
(5 ETH). L'attaquant n'a besoin d'aucune clé privée : la signature est publique
dans la transaction d'origine. Les fonds vont toujours au destinataire signé
(`to`), mais le vault paie plusieurs fois ce qui a été autorisé une fois.

## Cause racine
Le message signé n'est lié à rien d'unique :
- pas de **nonce** : rien n'empêche la réutilisation ;
- pas d'**expiration** : la signature ne périme jamais ;
- pas de **séparation de domaine** (adresse du contrat, chainId) : la signature
  pourrait aussi être rejouée sur un autre contrat ou une autre chaîne ;
- `ecrecover` brut : n'écarte ni les signatures malléables (`s` haut) ni les
  signatures invalides (retour silencieux de `address(0)`).

## Preuve (exploitation)
- Test : `test/exploits/SignatureReplay.t.sol`, `test_ExploitSucceeds_SignatureReplay`
- Résultat : PASS (gas 207346), voir `reports/signature-replay/forge-exploit.txt`
- Slither : voir `reports/signature-replay/slither-vulnerable.txt` et `.json`.

## Tri des résultats Slither (version vulnérable, 5 résultats)
| Détecteur | Verdict | Justification |
|---|---|---|
| **Rejeu (absence de nonce)** | **Non détecté par Slither** | Faille principale, prouvée uniquement par le test Forge |
| `arbitrary-send-eth` | Conséquence | Dangereux parce que la signature est rejouable |
| `missing-zero-check` (`_signer`) | Qualité, potentiellement grave | Un `signer` nul rendrait valide toute signature invalide |
| `missing-zero-check` (`to`) | Qualité | Non exploitable par un attaquant |
| `assembly` | Faux positif | Découpage voulu de la signature en r, s, v |
| `low-level-calls` | Faux positif | `call` volontaire, résultat vérifié par `require(ok)` |

Le linter de `forge build` signale en plus `ecrecover` : « ne rejette pas les
signatures malléables ». Slither ne l'a pas signalé.

**Limite de l'analyse statique :** Slither rate la faille la plus grave de ce
contrat. Seul le test Forge la révèle.

## Correctif
- Message signé en **EIP-712** (OpenZeppelin `EIP712`) avec `nonce` et `deadline`
  dans la structure : le domaine inclut automatiquement `chainId` et l'adresse du contrat.
- `nonce` consommé **avant** l'envoi d'ETH (Checks-Effects-Interactions).
- Vérification par `ECDSA.recover` : rejette signatures malléables et invalides.
- `require(block.timestamp <= deadline)`.
- `require` sur `_signer != address(0)` et `to != address(0)`.

## Validation
- Tests : `test/fixed/SignatureReplayFixed.t.sol`, 8 tests
  `reports/signature-replay/forge-fixed.txt`)
  - `test_LegitWithdrawWorks` : non-régression
  - `test_ProtectionHolds_ReplayBlocked` : le rejeu qui vidait le vault est bloqué
  - `test_ExpiredSignatureRejected` : expiration
  - `test_WrongSignerRejected` : mauvais signataire
  - `test_TamperedAmountRejected` : montant modifié
  - `test_MalleableSignatureRejected` : forme alternative (`s` haut) refusée
  - `test_CrossContractReplayBlocked` : séparation de domaine
  - `test_ZeroSignerRejected` : signer nul refusé
- Slither sur la version corrigée (`--filter-paths "lib"`, résultats d'OpenZeppelin
  exclus car hors périmètre) : 4 résultats, tous classés faux positifs ou risques
  acceptés. Voir `reports/signature-replay/slither-fixed.txt`.
  - `arbitrary-send-eth` : `to` fait partie du message signé
  - `reentrancy-events` : le nonce est déjà consommé avant le `call`
  - `timestamp` : dérive de quelques secondes sans impact sur une expiration de plusieurs minutes
  - `low-level-calls` : `call` volontaire et vérifié

## Risques résiduels
- Le **nonce global** impose d'utiliser les signatures dans l'ordre : une signature
  perdue bloque les suivantes. Un nonce par utilisateur serait plus souple.
- Le `signer` reste un point de défaillance unique (clé volée = fonds perdus).
- `block.timestamp` est légèrement manipulable par les validateurs.
- Une signature non expirée et au bon nonce reste utilisable par n'importe qui
  (le destinataire étant fixé par la signature) : choisir un `deadline` court.
- Les tests ne couvrent que le réseau local et des adresses fictives.
