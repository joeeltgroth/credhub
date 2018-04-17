package org.cloudfoundry.credhub.controller.v1;

import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.config.VersionProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class VersionController {

  private final String credhubVersion;
  private CEFAuditRecord auditRecord;

  @Autowired
  VersionController(VersionProvider versionProvider,
      CEFAuditRecord auditRecord) {
    this.auditRecord = auditRecord;
    this.credhubVersion = versionProvider.currentVersion();
  }

  @RequestMapping(method = RequestMethod.GET, path = "/version")
  public Map<String, ?> version() {
    auditRecord.setRequestDetails(() -> OperationDeviceAction.VERSION);

    return ImmutableMap.of("version", credhubVersion);
  }
}
