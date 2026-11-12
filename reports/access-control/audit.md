# Audit : Broken Access Control (AS-02)

## Résumé
| Champ | Contenu |
|---|---|
| Contrat audité | `src/vulnerable/VulnerableAdminBank.sol` |
| Contrat corrigé | `src/fixed/SecureAdminBank.sol` |
| Sévérité | **Critique** |
| Classification | CWE-284 (Improper Access Control), SWC-105 (Unprotected Ether Withdrawal) |

## Description
Les fonctions administratives (`setFeeRecipient`, `setFeeBps`, `pause`,
`transferOwnership`, `emergencyWithdraw`) ne vérifient pas `msg.sender`.
N'importe quelle adresse peut les appeler.

## Cause racine
Aucun contrôle de l'identité de l'appelant sur des fonctions sensibles.

## Impact
- Vol de tous les fonds déposés (`emergencyWithdraw`)
- Prise de contrôle du contrat (`transferOwnership`)
- Détournement des frais, jusqu'à 100 % (`setFeeRecipient`, `setFeeBps`)
- Déni de service : les utilisateurs ne peuvent plus retirer (`pause`)

## Preuve (exploitation)
`forge test --match-contract BrokenAccessControlExploitTest -vv` : 4/4 réussis.

## Résultats Slither (vulnérable)
| Détecteur | Fonction | Classement |
|---|---|---|
| arbitrary-send-eth | emergencyWithdraw | Confirmé (critique) |
| missing-zero-check | setFeeRecipient, transferOwnership | Confirmé (faible) |
| low-level-calls | withdraw | Faux positif |
| solc-version | pragma ^0.8.20 | Informatif |

Limite de l'outil : Slither n'a pas détecté l'absence de contrôle d'accès
sur setFeeBps, pause et setFeeRecipient. Ces failles sont prouvées par les
tests Forge et la revue manuelle.

## Correctif
- OpenZeppelin `AccessControl` : rôles ADMIN_ROLE et PAUSER_ROLE
- Séparation des pouvoirs : le pauser gèle, seul l'admin dégèle
- Suppression de `emergencyWithdraw` et `transferOwnership`
- Plafond des frais (`MAX_FEE_BPS` = 10 %) et vérification de `address(0)`
- Événements sur chaque changement de paramètre

## Validation
`forge test --match-contract BrokenAccessControlFixedTest -vv` : 8/8 réussis
(dont fuzzing 256 runs et invariant sur 128 000 appels). Slither : plus de
arbitrary-send-eth ni de missing-zero-check ; reste low-level-calls sur
withdraw (faux positif).

## Limites résiduelles
Si la clé admin est compromise, le contrat l'est aussi. Piste : multisig
et TimelockController.