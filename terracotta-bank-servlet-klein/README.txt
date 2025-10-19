/ In D:\Users\ERVELDEN\git_github\terracotta-bank\terracotta-bank-servlet-klein\src\test\java\com\joshcummings\codeplay\terracotta\service\SecretServiceTest.java werd op l. 38 een secret gebruikt,
/ in,
public class SecretServiceTest {
	private SecretService secretService;

//	@BeforeMethod
	@BeforeEach
	public void setUp() {
		this.secretService = new SecretService(
				new VaultTemplate(
						VaultEndpoint.from(URI.create("http://localhost:8200")),
						new TokenAuthentication("...")
				));
/ dat konden we niet inchecken,
/ we hebben hem in mijn rode aantekeningenboekje genoteerd,

remote: - GITHUB PUSH PROTECTION
remote:   —————————————————————————————————————————
remote:     Resolve the following violations before pushing again
remote:
remote:     - Push cannot contain secrets
remote:
remote:
remote:      (?) Learn how to resolve a blocked push
remote:      https://docs.github.com/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line#resolving-a-blocked-push
remote:
remote:
remote:       —— HashiCorp Vault Root Service Token ————————————————
remote:        locations:
remote:          - commit: 4624ab4a0aa1656075920931d39d5f9dcf93b957
remote:            path: terracotta-bank-servlet-klein/src/test/java/com/joshcummings/codeplay/terracotta/service/SecretServiceTest.java:38
remote:
remote:        (?) To push, remove secret from commit(s) or follow this URL to allow the secret.
remote:        https://github.com/ericjvandervelden/terracotta-bank/security/secret-scanning/unblock-secret/34IfsGt0dt98RJ9S2udU3XBeOln

/ we lezen op,
https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line#resolving-a-blocked-push

1. Remove the secret from your code.
2. To commit the changes, run git commit --amend --all. This updates the original commit that introduced the secret instead of creating a new commit.
3. Push your changes with git push.