package reencrypt;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

/**
 * Burp's persistence, backed by a plain map, so a {@link Config} can be built in a unit test.
 * Reads and writes behave like the real thing (including {@code getPreference}'s write-back); the map
 * is exposed so a test can seed stored values or assert what was saved.
 */
final class FakePersistence {

    private FakePersistence() {
    }

    static Persistence create() {
        return create(new HashMap<>());
    }

    static Persistence create(Map<String, Object> store) {
        PersistedObject persisted = (PersistedObject) Proxy.newProxyInstance(
                FakePersistence.class.getClassLoader(), new Class[] { PersistedObject.class },
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("toString")) {
                        return "fakePersistedObject";
                    }
                    if (name.startsWith("delete") && args != null && args.length == 1) {
                        store.remove(args[0]);
                        return null;
                    }
                    if (name.startsWith("get") && args != null && args.length == 1) {
                        return store.get(args[0]);
                    }
                    if (name.startsWith("set") && args != null && args.length == 2) {
                        store.put((String) args[0], args[1]);
                        return null;
                    }
                    return null;
                });
        return (Persistence) Proxy.newProxyInstance(FakePersistence.class.getClassLoader(),
                new Class[] { Persistence.class },
                (proxy, method, args) -> method.getName().equals("extensionData") ? persisted : null);
    }
}
