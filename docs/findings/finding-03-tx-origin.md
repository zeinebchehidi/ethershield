# Finding 03 : Authentification par tx.origin dans TxOriginWallet

| Champ | Valeur |
|---|---|
| **Sévérité** | Medium (impact élevé, probabilité faible à moyenne) |
| **Catégorie** | Contrôle d'accès / authentification fragile |
| **Contrat affecté** | `src/vulnerable/TxOriginWallet.sol`, fonction `transferTo()` (ligne 13) |
| **Contrat corrigé** | `src/fixed/TxOriginWalletFixed.sol` |

## Description
La fonction `transferTo()` autorise l'envoi de fonds avec `require(tx.origin == owner)`.
`tx.origin` désigne le compte qui a signé la transaction au départ, même si
l'appel passe par un contrat intermédiaire.

## Impact
Un attaquant déploie un contrat piège (faux « airdrop »). Si le propriétaire
l'appelle, ce contrat appelle `transferTo()` et le wallet accepte, car
`tx.origin` vaut encore le propriétaire. Tous les fonds sont envoyés à
l'attaquant. Dans le test : 5 ETH volés, solde du wallet = 0.

## Cause racine
Utilisation de `tx.origin` à la place de `msg.sender` pour l'autorisation.
Dans la chaîne `Owner -> Attacker -> Wallet`, `msg.sender` vaut `Attacker`
(l'appelant direct) alors que `tx.origin` vaut `Owner`.

## Preuve (exploitation)
- Test : `test/exploits/TxOrigin.t.sol`, `test_ExploitSucceeds_TxOriginPhishing`
- Résultat : PASS (gas 57790), voir `docs/txorigin-exploit-result.txt`
- Slither : détecteur `tx-origin` (Medium), voir `docs/slither-txorigin.txt`
  et `docs/slither-txorigin.json`

## Tri des résultats Slither (version vulnérable)
| Détecteur | Verdict | Justification |
|---|---|---|
| `tx-origin` | Faille confirmée | Exploit reproduit par test Forge |
| `arbitrary-send-eth` | Conséquence de la faille | Dangereux car l'authentification est contournable |
| `missing-zero-check` | Qualité (Low/Info) | Non exploitable par un attaquant, corrigé en bonus |
| `low-level-calls` | Faux positif | `call` volontaire, résultat vérifié par `require(ok)` |
| `immutable-states` | Optimisation gas | Sans lien avec la sécurité |

## Correctif
- Remplacement de `tx.origin` par `msg.sender` via OpenZeppelin `Ownable` et `onlyOwner`.
- Ajout de `require(to != address(0))` (finding `missing-zero-check`).
- Même nom de fonction conservé pour rejouer exactement la même attaque.

## Validation
- Tests : `test/fixed/TxOriginFixed.t.sol`, 3 PASS, voir `docs/txorigin-fixed-result.txt`
  - `test_ProtectionHolds_PhishingBlocked` : l'attaque revert avec
    `OwnableUnauthorizedAccount`, fonds intacts (5 ETH)
  - `test_OwnerCanStillTransfer` : non-régression, le propriétaire peut transférer
  - `test_ZeroAddressRejected` : adresse nulle refusée
- Slither sur la version corrigée : `tx-origin`, `arbitrary-send-eth`,
  `missing-zero-check` et `immutable-states` ont disparu, voir
  `docs/slither-txorigin-fixed.txt`.
  Restent 3 faux positifs informationnels : `pragma` et `solc-version`
  (contraintes `^0.8.20` dans OpenZeppelin, compilation réelle en 0.8.24) et
  `low-level-calls`.

## Risques résiduels
- Si le propriétaire signe directement une transaction malveillante (signature
  trompée, clé privée volée), le contrat ne peut rien faire.
- Un propriétaire unique reste un point de défaillance unique : un multisig serait plus sûr.
- Le transfert ou l'abandon de propriété (`transferOwnership`, `renounceOwnership`)
  est possible : à protéger en production.
- Les tests ne couvrent que les adresses fictives du laboratoire (réseau local).
