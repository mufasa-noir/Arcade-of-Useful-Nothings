# Java (Spring MVC/Boot): Source/Sink Catalog

Contents: sources, sinks, gotchas, Spring Security authorization, config pitfalls, grep seeds. Confirm framework and library versions: defaults changed significantly across releases.

## Sources
`@RequestParam`, `@PathVariable`, `@RequestBody` (Jackson-bound objects), `@RequestHeader`, `@CookieValue`, `@ModelAttribute` (form binding into objects), `HttpServletRequest.getParameter/getHeader/getInputStream/getParts`, multipart uploads, WebSocket/STOMP messages, JMS/Kafka payloads, stored data.

## Sinks and safe counterparts
| class | sink / pattern | safe counterpart / notes |
|-------|----------------|--------------------------|
| SQL (JDBC) | `Statement.executeQuery(concat)`, `createStatement` with string building, `JdbcTemplate.query(concat, ...)` | `PreparedStatement` with `?`, `NamedParameterJdbcTemplate` |
| SQL (JPA/Hibernate) | `createQuery`/`createNativeQuery` with concatenation, `@Query` with concatenation or SpEL on input, dynamic `ORDER BY` | named/positional parameters, Criteria API, allowlist sort fields (also check Spring Data `Sort` from request) |
| SQL (MyBatis) | `${param}` substitution | `#{param}` binding; `${}` only for allowlisted identifiers |
| Command | `Runtime.exec(String)`, `ProcessBuilder` with shell invocations (`sh -c`) and input | `ProcessBuilder` with argument list, no shell, validated args |
| Deserialization | `ObjectInputStream.readObject`, `XMLDecoder`, `XStream` without allowlist, Jackson polymorphic typing (`enableDefaultTyping`, `@JsonTypeInfo(use = Id.CLASS)`), SnakeYAML `new Yaml().load` on untrusted input (older defaults permit arbitrary types), Hessian/Kryo with open class registration | JSON into fixed types, deserialization filters (`ObjectInputFilter`), `SafeConstructor`, class allowlists |
| Expression/EL/JNDI | Spring `SpelExpressionParser` with `StandardEvaluationContext` on input, OGNL, EL evaluation of input, `InitialContext.lookup(userInput)` (JNDI injection class of bugs), `@Value`/SpEL with input | `SimpleEvaluationContext` for restricted evaluation; never evaluate input as expressions |
| Template | Thymeleaf expressions built from input (including fragment/view names from input), FreeMarker/Velocity `Template` from user strings | variables only; do not derive view names from request data |
| XXE | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` without secure-processing flags | disallow DOCTYPE (`disallow-doctype-decl`), disable external entities and access (`ACCESS_EXTERNAL_*`) |
| SSRF | `URL.openConnection`, `HttpClient`, `RestTemplate`, `WebClient`, Apache HttpClient with user URL | host allowlist, resolved-IP checks, redirect control |
| File | `new File(base, user)`, `Paths.get(base, user)` (no traversal protection), `ZipEntry` extraction (zip-slip), `Files.copy` to attacker-named paths, `ResourceLoader` with user input | `normalize()` and verify `startsWith(base)` after resolving; per-entry checks |
| Redirect | `redirect:` prefixed view names from input, `sendRedirect(user)`, `RedirectView` | validate against allowlist |
| Mass assignment | `@ModelAttribute`/`@RequestBody` bound directly into JPA entities exposing `role`, `id`, `owner`, `enabled` | DTOs with only allowed fields, `@JsonIgnore`, `setAllowedFields` |
| Logging | log injection (CRLF in logs), and logging libraries evaluating lookups from input in older versions | upgrade; sanitize |

## Authorization primitives (Spring Security)
- Configuration: `SecurityFilterChain` with `authorizeHttpRequests`/`requestMatchers` (newer) or `antMatchers`/`mvcMatchers` (older). **Rule order matters**: the first matching rule wins; a broad `permitAll` placed before a specific `hasRole` negates it. Check that the final rule is `anyRequest().authenticated()` or `denyAll()` rather than `permitAll`.
- Matcher semantics: pattern matching can differ between the security layer and the MVC layer (trailing slash, suffix patterns, case, path parameters/semicolons, encoded characters, context-path and servlet-path differences). A rule on `/admin/**` may not cover every URL variant the MVC mapping accepts; check the Spring version and path-matching settings.
- Method security: `@PreAuthorize`/`@PostAuthorize`/`@Secured` only work if method security is enabled (`@EnableMethodSecurity` or the older `@EnableGlobalMethodSecurity`) and the call goes through the Spring proxy (self-invocation bypasses it).
- Roles vs authorities: `hasRole('ADMIN')` adds the `ROLE_` prefix; mismatches between stored authority names and checks create silent allow/deny errors.
- Object-level: repositories like `findById(id)` return any object; ownership must be enforced in the query (`findByIdAndOwner`) or via `@PostAuthorize`/permission evaluators.
- CSRF: disabled globally (`csrf().disable()`) is acceptable for pure token-based APIs, a lead for cookie-authenticated apps.
- Actuator: `/actuator/*` endpoints (`env`, `heapdump`, `mappings`, `beans`, `httptrace`, `jolokia`) exposed without auth; check `management.endpoints.web.exposure.include` and security rules.
- Common wrong checks: UI-only role checks, checking authentication without roles, trusting a user ID from the body, authorization in a filter that is not applied to all dispatcher types or paths.

## Config pitfalls
Hard-coded secrets in `application.properties/yml` or committed profiles (`application-dev`), H2 console enabled, Swagger/OpenAPI UI exposing internal APIs, verbose error responses (`server.error.include-stacktrace`), permissive CORS (`allowedOrigins("*")` with credentials via patterns), `spring.jackson` default typing, outdated dependencies with known deserialization or expression-injection issues (check reachability).

## Grep seeds
```bash
rg -n '@(Request|Get|Post|Put|Delete|Patch)Mapping|@RestController|@Controller' --glob '*.java' --glob '*.kt'
rg -n '@RequestParam|@PathVariable|@RequestBody|@ModelAttribute|getParameter\(' --glob '*.java' --glob '*.kt'
rg -n 'createStatement|executeQuery\(|createQuery\(|createNativeQuery\(|@Query|\$\{' --glob '*.java' --glob '*.xml' --glob '*.kt'
rg -n 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder' --glob '*.java' --glob '*.kt'
rg -n 'ObjectInputStream|readObject|XMLDecoder|XStream|enableDefaultTyping|JsonTypeInfo|new Yaml\(' --glob '*.java' --glob '*.kt'
rg -n 'SpelExpressionParser|StandardEvaluationContext|InitialContext|\.lookup\(' --glob '*.java' --glob '*.kt'
rg -n 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|disallow-doctype' --glob '*.java'
rg -n 'openConnection|RestTemplate|WebClient|HttpClient' --glob '*.java' --glob '*.kt'
rg -n 'permitAll|authenticated\(\)|hasRole|hasAuthority|antMatchers|requestMatchers|PreAuthorize|EnableMethodSecurity|csrf\(\)' --glob '*.java' --glob '*.kt'
rg -n 'management\.endpoints|actuator|spring\.h2|springdoc|swagger' --glob '*.properties' --glob '*.yml' --glob '*.yaml'
```
