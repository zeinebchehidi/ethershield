# Audit : Reentrancy (AS-01)

## Résumé
| Champ | Contenu |
|---|---|
| Contrat audité | `src/vulnerable/VulnerableBank.sol` |
| Contrat corrigé | `src/fixed/SecureBank.sol` |
| Sévérité | **Critique** |
| Classification | SWC-107 (Reentrancy), CWE-841 |

## Description
`withdraw()` envoie l'ETH à l'appelant (`msg.sender.call`) avant de remettre son
solde à zéro. Un contrat malveillant peut rappeler `withdraw()` depuis sa fonction
`receive()` tant que son solde n'est pas mis à jour.

## Cause racine
Violation du schéma Checks-Effects-Interactions : interaction externe avant la
mise à jour de l'état.

## Impact
Vol de tous les fonds de la banque. Dans le test, un attaquant mise 1 ETH et
récupère 11 ETH (les 10 ETH de la victime).

## Preuve (exploitation)
`forge test --match-test test_ReentrancyDrainsBank -vv` : réussi.
Banque : 0 ETH après l'attaque ; attaquant : 11 ETH.

## Résultats Slither (vulnérable)
| Détecteur | Fonction | Classement |
|---|---|---|
| reentrancy-eth | withdraw | Confirmé (critique) |
| low-level-calls | withdraw | Faux positif |
| solc-version | pragma ^0.8.20 | Informatif |

## Correctif
- Checks-Effects-Interactions : `balances[msg.sender] = 0` avant l'envoi d'ETH
- `ReentrancyGuard` d'OpenZeppelin (`nonReentrant`) : défense en profondeur

## Validation
`forge test --match-contract ReentrancyTest -vv` : 3/3 réussis
- l'attaque échoue sur SecureBank et la banque conserve ses 10 ETH ;
- un retrait légitime fonctionne toujours (2 ETH rendus, solde à 0).
Slither (corrigé) : `reentrancy-eth` disparu ; reste `low-level-calls` (faux positif).

## Limites résiduelles
- `nonReentrant` ne couvre pas la reentrancy entre plusieurs contrats ni la
  read-only reentrancy.
- Le pattern pull payment reste la référence pour les cas complexes.
- Toute nouvelle fonction envoyant de l'ETH doit respecter les mêmes règles et
  recevoir ses propres tests.