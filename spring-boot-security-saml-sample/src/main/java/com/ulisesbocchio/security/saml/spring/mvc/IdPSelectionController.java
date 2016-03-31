package com.ulisesbocchio.security.saml.spring.mvc;

/**
 * @author Ulises Bocchio
 */

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

@Controller
@RequestMapping("/idpselection")
@Slf4j
public class IdPSelectionController {

    @Autowired
    private MetadataManager metadataManager;

    @RequestMapping
    public ModelAndView idpSelection(HttpServletRequest request) {

        if (comesFromDiscoveryFilter(request)) {
            ModelAndView idpSelection = new ModelAndView("idpselection");
            idpSelection.addObject(SAMLDiscovery.RETURN_URL, request.getAttribute(SAMLDiscovery.RETURN_URL));
            idpSelection.addObject(SAMLDiscovery.RETURN_PARAM, request.getAttribute(SAMLDiscovery.RETURN_PARAM));
            Map<String, String> idpNameAliasMap = metadataManager.getIDPEntityNames().stream()
                    .collect(toMap(identity(), this::getAlias));
            idpSelection.addObject("idpNameAliasMap", idpNameAliasMap);
            return idpSelection;
        }
        throw new AuthenticationServiceException("SP Discovery flow not detected");
    }

    @SneakyThrows
    private String getAlias(String entityId) {
        return metadataManager.getExtendedMetadata(entityId).getAlias();
    }

    private boolean comesFromDiscoveryFilter(HttpServletRequest request) {
        return request.getAttribute(SAMLConstants.LOCAL_ENTITY_ID) != null &&
                request.getAttribute(SAMLDiscovery.RETURN_URL) != null &&
                request.getAttribute(SAMLDiscovery.RETURN_PARAM) != null;
    }

}
