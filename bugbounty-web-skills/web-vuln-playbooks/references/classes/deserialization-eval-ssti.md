# Deserialization, Dynamic Evaluation, SSTI, Prototype Pollution

**Root cause:** attacker data is parsed into objects with behavior (or into code/templates), so loading it triggers method calls, class instantiation, or code execution.

## What the sink looks like
- Native object deserialization: PHP `unserialize` (and wrappers like `maybe_unserialize`), Python `pickle`/`marshal`/`shelve`/unsafe `yaml.load`, Java `ObjectInputStream.readObject`/`XMLDecoder`/`XStream`/Jackson with polymorphic default typing/SnakeYAML unsafe load, .NET binary formatters, Ruby `Marshal.load`/unsafe YAML, Node libraries that revive functions.
- Eval-like: `eval`, `exec`, `Function(...)`, `vm` run on input, `assert` with strings (old PHP), `create_function`, dynamic includes/imports with input, expression languages (SpEL, OGNL, EL, JEXL), `call_user_func` with attacker-chosen names.
- SSTI: rendering a template built from user input (`render_template_string`, `Template(user)`, EJS/Pug/Handlebars/Twig/Velocity/FreeMarker with user-controlled source or options).
- Prototype pollution (JS): recursive merge/clone/set with attacker-controlled keys (`__proto__`, `constructor.prototype`), later read by gadgets (options objects, auth flags, template/child-process options).

## Safe vs unsafe
- Safe: data-only formats (JSON) parsed into plain data and validated; safe loaders (`yaml.safe_load`); class allowlists for deserialization; signed-and-verified blobs where the signing key is secret; templates loaded from files with user data only as variables; sandboxed template engines (and knowing their limits).
- Unsafe: signature checks that are optional or use a known/default key; allowlists implemented as blocklists; user-controlled template strings; merge functions without key filtering.

## Reachability and impact
Deserialization needs both attacker control *and* a usable gadget chain in loaded code; say what you can verify (the sink and the data flow) and what is unknown (gadgets), and avoid claiming RCE without a verified chain. SSTI and eval with attacker input are direct code execution paths and usually critical. Prototype pollution matters through its gadgets; identify one concrete gadget or mark as speculative.

## Review questions
- Where does the serialized or template data come from; is it signed or encrypted, and by what key?
- Is the loader's safe mode used? Which classes can be instantiated?
- Is the template source constant, or does input influence the source, name or options?
- For merges: are `__proto__`/`constructor`/`prototype` keys blocked; which objects later consume inherited properties?

## False-positive traps
Data only comes from the server's own cookies signed with a secret not controllable; test fixtures; admin-only loaders where scope excludes; template engine with input only as variables.

## Variant ideas
Cookies/session blobs, cache and queue payloads, import/restore features, plugin options stored serialized (WordPress options), file metadata (phar-style wrappers in older PHP versions), webhook payload handlers, email template editors.
