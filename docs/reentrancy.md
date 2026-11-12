# Reentrancy

## 1. Définition

La **reentrancy** (réentrance) survient quand un contrat envoie de l'ETH (ou appelle
un contrat externe) **avant** d'avoir mis à jour son propre état. Si le destinataire
est un contrat, sa fonction `receive()` peut rappeler le contrat d'origine pendant que
l'état est encore ancien, et répéter l'opération autant de fois que les fonds le
permettent.

- Classification : SWC-107 (Reentrancy), CWE-841 (Improper Enforcement of Behavioral Workflow)
- Sévérité : **Critique**

## 2. Contrat vulnérable

Fichier : `src/vulnerable/VulnerableBank.sol`

Une banque simple : dépôt, retrait total, consultation du solde global.

```solidity
function withdraw() external {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Solde nul");

    // BUG : l'ether est envoyé AVANT la mise à jour du solde
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "Transfert echoue");

    balances[msg.sender] = 0;
}
```

Le solde de l'appelant n'est remis à zéro **qu'après** l'envoi. Pendant l'appel
`call`, `balances[msg.sender]` contient donc toujours l'ancienne valeur.

## 3. Exploitation

Fichier de test : `test/Reentrancy.t.sol` (contrats `Attacker` et `ReentrancyTest`)

Le contrat `Attacker` :
1. dépose 1 ETH dans la banque (`attack()`), puis appelle `withdraw()` ;
2. quand la banque lui envoie l'ETH, sa fonction `receive()` est déclenchée ;
3. `receive()` rappelle `withdraw()` tant que la banque contient au moins 1 ETH ;
4. à chaque rappel, le solde de l'attaquant n'a pas encore été remis à zéro, donc le
   `require(amount > 0)` passe encore.

Scénario du test `test_ReentrancyDrainsBank` :

| Étape | État |
|---|---|
| Avant l'attaque | La victime a déposé 10 ETH ; la banque contient 10 ETH |
| Mise de l'attaquant | 1 ETH déposé, la banque contient 11 ETH |
| Après l'attaque | Banque : **0 ETH** ; attaquant : **11 ETH** |

L'attaquant a misé 1 ETH et en récupère 11 : il a volé les 10 ETH de la victime.

Résultat : **le test réussit**, donc l'attaque fonctionne sur le contrat vulnérable.

```bash
forge test --match-test test_ReentrancyDrainsBank -vv
```

## 4. Analyse statique

Le linter de Foundry signale la faille dès la compilation :

```
warning[reentrancy-eth]: uncapped ETH transfer can be reentered before `balances` is updated
   src/vulnerable/VulnerableBank.sol:17
```

Rapports Slither :
- `reports/reentrancy/slither-reentrancy-vulnerable.txt`
- `reports/reentrancy/slither-reentrancy-fixed.txt`

| Détecteur | Fonction | Classement |
|---|---|---|
| `reentrancy-eth` | `withdraw` | Confirmé (critique) |
| `low-level-calls` | `withdraw` | Faux positif |
| `solc-version` | pragma `^0.8.20` | Informatif |

Slither détecte ici directement la faille : l'appel externe (ligne 17) précède
l'écriture de `balances[msg.sender] = 0` (ligne 20). Il signale en plus que
`balances` est exposée à une reentrancy inter-fonctions (`deposit`, `withdraw`).

Sur `SecureBank.sol`, `reentrancy-eth` n'est plus signalé ; il ne reste que
`low-level-calls` (faux positif).

## 5. Cause racine

Violation du schéma **Checks-Effects-Interactions** : l'interaction externe (envoi
d'ETH) a lieu avant l'effet (mise à jour du solde). L'état du contrat est donc
incohérent pendant l'appel externe.

## 6. Correction

Fichier : `src/fixed/SecureBank.sol`

Deux protections combinées (défense en profondeur) :

1. **Checks-Effects-Interactions** : le solde est mis à zéro **avant** l'envoi d'ETH.
   Si l'attaquant rappelle `withdraw()`, le `require(amount > 0)` échoue.
2. **`ReentrancyGuard` d'OpenZeppelin** : le modificateur `nonReentrant` interdit tout
   rappel de la fonction pendant son exécution, même si un défaut de logique
   réapparaît plus tard.

```solidity
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Solde nul");

    // Checks-Effects-Interactions : on met à jour AVANT d'envoyer
    balances[msg.sender] = 0;

    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "Transfert echoue");
}
```

## 7. Validation

| Test | Ce qui est vérifié |
|---|---|
| `test_ReentrancyDrainsBank` | L'attaque réussit sur `VulnerableBank` (preuve de la faille) |
| `test_SecureBankBlocksReentrancy` | L'attaque échoue sur `SecureBank` (revert) et la banque garde ses 10 ETH |
| `test_SecureBankLegitWithdrawStillWorks` | Un utilisateur légitime retire toujours ses fonds (2 ETH) et son solde passe à 0 |

Résultat : **3/3 tests réussis**.

Pourquoi l'attaque échoue sur `SecureBank` : le rappel de `withdraw()` depuis
`receive()` est rejeté par `nonReentrant`. Ce revert fait échouer l'envoi d'ETH
(`ok == false`), donc le `require(ok, ...)` annule toute la transaction, y compris
le dépôt de l'attaquant.

```bash
forge test --match-contract ReentrancyTest -vv
```

## 8. Limites résiduelles

- `nonReentrant` protège **un contrat à la fois** : une reentrancy entre plusieurs
  contrats, ou une *read-only reentrancy* (lecture d'un état incohérent via une
  fonction `view`), n'est pas couverte.
- Le retrait par `call` reste vulnérable à un destinataire qui refuse l'ETH (revert
  volontaire). Cela bloque uniquement son propre retrait, mais le pattern
  **pull payment** reste la référence pour les cas complexes.
- Les tests couvrent le scénario du `withdraw()` ; toute nouvelle fonction qui envoie
  de l'ETH doit respecter les mêmes règles et recevoir ses propres tests.

## 9. Reproduction

```bash
forge build
forge test --match-contract ReentrancyTest -vv
slither src/vulnerable/VulnerableBank.sol --filter-paths "lib|test"
slither src/fixed/SecureBank.sol --filter-paths "lib|test"
```

Tous les tests s'exécutent sur un réseau local avec des comptes et des fonds fictifs.