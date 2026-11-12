# Broken Access Control

## 1. Définition

Le **Broken Access Control** (contrôle d'accès défaillant) survient quand un smart
contract expose des fonctions sensibles sans vérifier **qui** les appelle. Sur
Ethereum, toute fonction `external` ou `public` est appelable par n'importe quelle
adresse : c'est au développeur de restreindre explicitement l'accès (via
`msg.sender`, des modificateurs ou des rôles).

- Classification : CWE-284 (Improper Access Control), SWC-105 (Unprotected Ether Withdrawal)
- Sévérité : **Critique**

## 2. Contrat vulnérable

Fichier : `src/vulnerable/VulnerableAdminBank.sol`

Le contrat est une banque (dépôt / retrait) avec des fonctions d'administration
qui ne vérifient jamais `msg.sender` :

| Fonction | Rôle prévu | Problème |
|---|---|---|
| `setFeeRecipient(address)` | Définir qui reçoit les frais | Appelable par tous |
| `setFeeBps(uint256)` | Fixer le taux de frais | Appelable par tous, aucun plafond |
| `pause()` | Geler la banque | Appelable par tous |
| `transferOwnership(address)` | Changer le propriétaire | Appelable par tous |
| `emergencyWithdraw()` | Retrait d'urgence | Envoie TOUT le solde à l'appelant |

Exemple de code fautif :

```solidity
function emergencyWithdraw() external {
    (bool ok, ) = msg.sender.call{value: address(this).balance}("");
    require(ok, "transfer failed");
}
```

## 3. Exploitation

Fichier de test : `test/BrokenAccessControl.t.sol` (contrat `BrokenAccessControlExploitTest`)

Scénario : Alice dépose 10 ETH (fictifs) dans la banque, puis un attaquant, qui n'a
aucun rôle, appelle les fonctions administratives.

| Test | Attaque | Impact |
|---|---|---|
| `test_Exploit_StealAllFunds` | `emergencyWithdraw()` | L'attaquant récupère les 10 ETH |
| `test_Exploit_TakeOwnership` | `transferOwnership(attacker)` | L'attaquant devient `owner` |
| `test_Exploit_RedirectFees` | `setFeeRecipient` + `setFeeBps(10000)` | Frais de 100 % versés à l'attaquant |
| `test_Exploit_FreezeBank` | `pause()` | Alice ne peut plus retirer ses fonds (déni de service) |

Résultat : **4/4 tests réussis**, ce qui signifie que les 4 attaques fonctionnent sur
le contrat vulnérable.

```bash
forge test --match-contract BrokenAccessControlExploitTest -vv
```

## 4. Analyse statique (Slither)

Rapport : `reports/access-control/slither-vulnerable.txt`

| Détecteur | Fonction | Classement |
|---|---|---|
| `arbitrary-send-eth` | `emergencyWithdraw` | Confirmé (critique) |
| `missing-zero-check` | `setFeeRecipient`, `transferOwnership` | Confirmé (faible) |
| `low-level-calls` | `withdraw` | Faux positif (le `call` est la bonne pratique, débit avant envoi) |
| `solc-version` | pragma `^0.8.20` | Informatif |

**Limite de l'outil** : Slither n'a pas signalé l'absence de contrôle d'accès sur
`setFeeBps`, `pause` et `setFeeRecipient`. Il ne peut pas deviner quelles fonctions
doivent être réservées à un administrateur, car cela dépend de la logique métier. Ces
failles ont été prouvées par les tests Forge et la revue manuelle.

## 5. Cause racine

Aucune vérification de l'identité de l'appelant (`msg.sender`) sur des fonctions qui
modifient l'état critique du contrat ou déplacent des fonds.

## 6. Correction

Fichier : `src/fixed/SecureAdminBank.sol`

Le correctif repose sur `AccessControl` d'OpenZeppelin :

1. **Rôles** : `ADMIN_ROLE` (frais, bénéficiaire, dégel) et `PAUSER_ROLE` (gel).
2. **Séparation des pouvoirs** : le pauser peut geler la banque mais pas la dégeler ;
   seul l'admin le peut.
3. **Suppression des fonctions dangereuses** : `emergencyWithdraw` et
   `transferOwnership` n'existent plus. Les fonds ne sortent que par `withdraw()`,
   et les droits se gèrent par `grantRole` / `revokeRole`.
4. **Bornes métier** : `MAX_FEE_BPS = 1000` (10 % maximum), même pour l'admin.
5. **Validation des entrées** : refus de `address(0)`.
6. **Traçabilité** : événements `FeeRecipientChanged`, `FeeBpsChanged`, `PausedChanged`.

```solidity
function setFeeBps(uint256 b) external onlyRole(ADMIN_ROLE) {
    require(b <= MAX_FEE_BPS, "fee too high");
    feeBps = b;
    emit FeeBpsChanged(b);
}
```

## 7. Validation

Contrat de test : `BrokenAccessControlFixedTest`

| Test | Ce qui est vérifié |
|---|---|
| `test_Fixed_AttackerCannotSetFee` | L'attaquant est rejeté (`AccessControlUnauthorizedAccount`) |
| `test_Fixed_AttackerCannotRedirectFees` | Idem pour le bénéficiaire des frais |
| `test_Fixed_AttackerCannotPause` | Idem pour la pause |
| `test_Fixed_AdminCannotExceedFeeCap` | L'admin ne peut pas dépasser 10 % |
| `test_Fixed_PauserCannotUnpause` | Séparation des rôles respectée |
| `test_Fixed_UserKeepsFunds` | Un utilisateur légitime retire toujours ses fonds |
| `testFuzz_OnlyAdminSetsFee` | 256 combinaisons aléatoires : seul l'admin modifie les frais |
| `invariant_FeeBelowCap` | 256 séquences, 128 000 appels : les frais ne dépassent jamais le plafond |

Résultat : **8/8 tests réussis**. Slither sur le contrat corrigé : plus de
`arbitrary-send-eth` ni de `missing-zero-check` ; il reste `low-level-calls` sur
`withdraw` (faux positif).

```bash
forge test --match-contract BrokenAccessControlFixedTest -vv
slither src/fixed/SecureAdminBank.sol --filter-paths "lib|test"
```

## 8. Limites résiduelles

- Si la **clé privée de l'admin est compromise**, le contrat l'est aussi.
  Pistes : multisig et `TimelockController` pour retarder les actions sensibles.
- Les rôles sont gérés par `DEFAULT_ADMIN_ROLE` : il faut protéger ce rôle avec le
  même soin.
- Les tests couvrent les fonctions identifiées ; une nouvelle fonction ajoutée plus
  tard sans `onlyRole` réintroduirait la faille. Les tests de non-régression et la
  revue de code doivent être maintenus.

## 9. Reproduction

```bash
forge build
forge test --match-path test/BrokenAccessControl.t.sol -vv
slither src/vulnerable/VulnerableAdminBank.sol --filter-paths "lib|test"
slither src/fixed/SecureAdminBank.sol --filter-paths "lib|test"
```

Tous les tests s'exécutent sur un réseau local avec des comptes et des fonds fictifs.