# plg_authorization_relaxed
A relaxed Joomla authorization plugin ignoring CAPS-LOCK and wrong capitalization

This authentication plugin accepts not only the "real" user password but also two variations that could result from CAPS-LOCK being wrongly engaged or some smartphone/tablet forcing the capitalization of the entered password.

As an example, if the "real" password is "mySecretPassword", also "MYsECRETpASSWORD" and "MySecretPassword" will be accepted as valid.

Due to the "relaxed" acceptation rules a small security reduction is introduced which will be more than compensated by adding a single character to any password.
