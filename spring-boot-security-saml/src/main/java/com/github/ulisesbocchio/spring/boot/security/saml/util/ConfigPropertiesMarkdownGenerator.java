package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.metadata.*;
import org.springframework.boot.configurationprocessor.metadata.ItemMetadata.ItemType;

import javax.tools.Diagnostic;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Comparator;
import java.util.Optional;

/**
 * Not used as part of the library runtime. Just a utility class to parse Spring's {@code spring-configuration-metadata.json}
 * file into a MarkDown table to be placed in the documentation page.
 *
 * @author Ulises Bocchio
 */
public class ConfigPropertiesMarkdownGenerator {
    public static void main(String[] args) throws IOException {
        String basePath = System.getProperty("project.root");
        ConfigurationMetadata metadata = readMetadata(new FileInputStream(new File(basePath, "target/classes/META-INF/spring-configuration-metadata.json")));
        metadata.getItems().stream()
                .map(ItemMetadata::new)
                .filter(i -> i.isOfItemType(ItemType.PROPERTY))
                .distinct()
                .sorted(Comparator.comparing(ItemMetadata::getGroup).thenComparing(ItemMetadata::getName))
                .forEach(i -> System.out.printf("|%s\t|%s\t|%s\t|\n", i.getName(), i.getDefaultValue(), i.getDescription()));
    }

    private static ConfigurationMetadata readMetadata(InputStream in) {
        try {
            return new JsonMarshaller().read(in);
        } catch (JSONException ex) {
            throw new InvalidConfigurationMetadataException(
                    "Invalid meta-data: "
                            + ex.getMessage(),
                    Diagnostic.Kind.ERROR);
        } catch (Exception ex) {
            return null;
        } finally {
            // Close without throwing an exception
            try {
                in.close();
            } catch (IOException e) {
            }
        }
    }

    private static class ItemMetadata {

        private org.springframework.boot.configurationprocessor.metadata.ItemMetadata delegate;

        private ItemMetadata(org.springframework.boot.configurationprocessor.metadata.ItemMetadata delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof ItemMetadata) {
                return delegate.getName().equals(((ItemMetadata) obj).getDelegate().getName());
            }
            return false;
        }

        @Override
        public int hashCode() {
            return delegate.getName().hashCode();
        }

        public org.springframework.boot.configurationprocessor.metadata.ItemMetadata getDelegate() {
            return delegate;
        }

        public boolean isOfItemType(ItemType type) {
            return delegate.isOfItemType(type);
        }

        public String getName() {
            return delegate.getName();
        }

        public String getGroup() {
            return delegate.getName().substring(0, delegate.getName().lastIndexOf("."));
        }

        public Object getDefaultValue() {
            return delegate.getDefaultValue();
        }

        public String getDescription() {
            return Optional.of(delegate)
                    .map(i -> i.getDescription())
                    .map(d -> d.replaceAll("\n", " "))
                    .orElse(null);
        }
    }
}
