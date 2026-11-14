# Audit : Denial of Service (AS-06)

## Résumé
| Champ | Contenu |
|---|---|
| Contrats audités | `src/vulnerable/VulnerableAuction.sol`, `src/vulnerable/VulnerableAirdrop.sol` |
| Contrats corrigés | `src/fixed/SecureAuction.sol`, `src/fixed/SecureAirdrop.sol` |
| Sévérité | **Haute** |
| Classification | SWC-113 (DoS with Failed Call), SWC-128 (DoS With Block Gas Limit), CWE-400, CWE-834 |

## Description
- `VulnerableAuction.bid()` rembourse l'ancien meilleur enchérisseur par un envoi
  d'ETH dont l'échec annule toute la transaction (`require(ok)`).
- `VulnerableAirdrop.distribute()` envoie l'ETH à tous les participants dans une
  boucle non bornée, et `register()` n'a ni plafond ni dédoublonnage.

## Cause racine
Le contrat dépend d'une action externe qu'il ne contrôle pas (réception d'ETH par un
tiers, taille d'un tableau contrôlée par l'attaquant) : une défaillance individuelle
devient une défaillance globale.

## Impact
- Enchère bloquée définitivement : plus personne ne peut surenchérir, l'attaquant
  gagne au prix qu'il a choisi (V1)
- Distribution bloquée par un seul participant hostile ; fonds immobilisés dans le
  contrat (V2) : 3 ETH dans le test
- Distribution impossible par épuisement de gas ; fonds immobilisés (V3) : 100 ETH
  dans le test, pour 1 500 inscriptions de l'attaquant

## Preuve (exploitation)
`forge test --match-contract DenialOfServiceExploitTest -vv` : 5/5 réussis.

| Test | Résultat |
|---|---|
| `test_Exploit_AuctionBlockedByRevertingBidder` | Bob ne peut plus miser ; l'attaquant reste en tête |
| `testFuzz_Exploit_NoOneCanOutbid` | Aucun montant ne permet de surenchérir (256 runs) |
| `test_Exploit_AirdropBlockedByRevertingParticipant` | `distribute()` revert à chaque essai ; 3 ETH bloqués |
| `test_Exploit_AirdropGasExhaustion` | `distribute()` manque de gas ; 100 ETH bloqués |
| `test_Exploit_AirdropGasGrowsLinearly` | Coût croissant avec le nombre de participants |

## Résultats Slither (vulnérable)
| Contrat | Détecteur | Fonction | Classement |
|---|---|---|---|
| VulnerableAuction | low-level-calls | bid | Faux positif |
| VulnerableAuction | solc-version | pragma ^0.8.20 | Informatif |
| VulnerableAirdrop | calls-loop | distribute | Confirmé (faible) |
| VulnerableAirdrop | low-level-calls | distribute | Faux positif |
| VulnerableAirdrop | immutable-states | owner | Optimisation |
| VulnerableAirdrop | solc-version | pragma ^0.8.20 | Informatif |

Le linter de Foundry signale en plus `arbitrary-send-eth` sur le remboursement de
`VulnerableAuction` (ligne 24), pour une autre raison que le blocage.

Limite de l'outil : Slither ne signale aucune faille de déni de service sur
`VulnerableAuction` (le blocage dépend du `receive()` d'un contrat tiers). Sur
`VulnerableAirdrop`, `calls-loop` est le seul indice ; aucun détecteur n'évalue
une boucle non bornée ni l'inscription ouverte à tous. Ces failles sont prouvées
par les tests Forge et la revue manuelle.

Slither (corrigé) : `calls-loop` a disparu ; il ne reste que `low-level-calls` sur
`withdraw` et `claim` (faux positif).

## Correctif
- `SecureAuction` : pull payment (`pendingReturns` + `withdraw()`), Checks-Effects-Interactions,
  `ReentrancyGuard`, événements
- `SecureAirdrop` : suppression de la boucle (réclamation individuelle `claim()`),
  part figée par `openClaims()`, inscription dédoublonnée et plafonnée
  (`MAX_PARTICIPANTS` = 1000), `ReentrancyGuard`

## Validation
`forge test --match-contract DenialOfServiceFixedTest -vv` : 13/13 réussis
(dont 2 tests de fuzzing, 256 runs chacun).
`forge test --match-contract DenialOfServiceInvariantTest -vv` : invariant de
solvabilité de l'enchère respecté sur 256 séquences (128 000 appels).
Mesures de gas : `distribute()` coûte 221 410 gas pour 20 participants et
1 926 550 pour 200 ; `claim()` coûte 64 917 gas avec 1 000 participants.
- un enchérisseur hostile ne peut bloquer que son propre retrait ;
- un participant hostile ne bloque pas les réclamations des autres ;
- le gas de `claim()` reste sous 100 000 avec 1 000 participants ;
- un utilisateur légitime récupère toujours ses fonds.

## Limites résiduelles
- Le plafond d'inscription peut être saturé par un attaquant (liste blanche ou
  mise en jeu recommandées).
- ETH forcé par `selfdestruct` (SWC-132) et return bomb non couverts par les tests.
- Fonds non réclamés : prévoir une échéance et une récupération par l'owner.
