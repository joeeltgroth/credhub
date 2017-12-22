package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateDataService;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Fail.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PermissionedCertificateServiceTest {
  private PermissionedCertificateService subject;
  private PermissionedCredentialService permissionedCredentialService;
  private CertificateDataService certificateDataService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;
  private CertificateVersionDataService certificateVersionDataService;
  private UUID uuid;

  @Before
  public void beforeEach() {
    permissionedCredentialService = mock(PermissionedCredentialService.class);
    certificateDataService = mock(CertificateDataService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    certificateDataService = mock(CertificateDataService.class);
    userContextHolder = mock(UserContextHolder.class);
    certificateVersionDataService = mock(CertificateVersionDataService.class);
    subject = new PermissionedCertificateService(permissionedCredentialService, certificateDataService, permissionCheckingService, userContextHolder, certificateVersionDataService);
  }

  @Test
  public void save_whenTransitionalIsFalse_delegatesToPermissionedCredentialService() throws Exception {
    CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(false);
    BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    subject.save(
        mock(CredentialVersion.class),
        value,
        generateRequest,
        newArrayList()
    );

    Mockito.verify(generateRequest).setType(eq("certificate"));
    Mockito.verify(permissionedCredentialService).save(any(),
        eq(value),
        eq(generateRequest),
        any()
    );
  }

  @Test
  public void save_whenTransitionalIsTrue_andThereAreNoOtherTransitionalVersions_delegatesToPermissionedCredentialService() throws Exception {
    CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(true);

    BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("/some-name");

    CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(false);

    when(permissionedCredentialService.findAllByName(eq("/some-name"), any()))
        .thenReturn(newArrayList(previousVersion));

    subject.save(
        mock(CredentialVersion.class),
        value,
        generateRequest,
        newArrayList()
    );

    Mockito.verify(generateRequest).setType(eq("certificate"));
    Mockito.verify(permissionedCredentialService).save(any(),
        eq(value),
        eq(generateRequest),
        any()
    );
  }

  @Test
  public void save_whenTransitionalIsTrue_AndThereIsAnotherTransitionalVersion_throwsAnException() throws Exception {
    CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(true);

    BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("/some-name");

    CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(true);

    when(permissionedCredentialService.findAllByName(eq("/some-name"), any()))
        .thenReturn(newArrayList(previousVersion));

    try {
      subject.save(
          mock(CredentialVersion.class),
          value,
          generateRequest,
          newArrayList()
      );
      fail("should throw exception");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.too_many_transitional_versions"));
    }
  }

  @Test
  public void getAll_returnsAllCertificatesTheCurrentUserCanAccess() throws Exception {
    Credential myCredential = mock(Credential.class);
    when(myCredential.getName()).thenReturn("my-credential");
    Credential yourCredential = mock(Credential.class);
    when(yourCredential.getName()).thenReturn("your-credential");

    UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);
    when(permissionCheckingService.hasPermission(user, "your-credential", PermissionOperation.READ)).thenReturn(false);

    when(certificateDataService.findAll())
        .thenReturn(newArrayList(myCredential, yourCredential));

    final List<Credential> certificates = subject.getAll(newArrayList());
    assertThat(certificates, equalTo(newArrayList(myCredential)));
  }

  @Test
  public void getAllByName_returnsCertificateWithMatchingNameIfCurrentUserHasAccess() throws Exception {
    Credential myCredential = mock(Credential.class);
    when(myCredential.getName()).thenReturn("my-credential");
    Credential otherCredential = mock(Credential.class);
    when(otherCredential.getName()).thenReturn("other-credential");

    UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);
    when(permissionCheckingService.hasPermission(user, "other-credential", PermissionOperation.READ)).thenReturn(true);

    when(certificateDataService.findByName("my-credential"))
        .thenReturn(myCredential);

    final List<Credential> certificates = subject.getByName("my-credential", newArrayList());
    assertThat(certificates, equalTo(newArrayList(myCredential)));
  }

  @Test
  public void getVersions_returnsListWithVersions() throws Exception {
    CredentialVersion myCredential = mock(CredentialVersion.class);
    when(myCredential.getName()).thenReturn("my-credential");
    CredentialVersion secondVersion = mock(CredentialVersion.class);
    when(secondVersion.getName()).thenReturn("my-credential");

    List<CredentialVersion> versions = newArrayList(myCredential, secondVersion);

    UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);

    uuid = UUID.randomUUID();
    when(certificateVersionDataService.findAllVersions(uuid))
        .thenReturn(versions);

    final List<CredentialVersion> certificates = subject.getVersions(uuid, false, newArrayList());
    assertThat(certificates, equalTo(versions));
  }

  @Test
  public void getVersions_withCurrentTrue_returnsCurrentVersions() throws Exception {
    Credential aCredential = new Credential("my-credential");

    CredentialVersion credentialVersion1 = mock(CredentialVersion.class);
    when(credentialVersion1.getName()).thenReturn("my-credential");
    CredentialVersion credentialVersion2 = mock(CredentialVersion.class);
    when(credentialVersion2.getName()).thenReturn("my-credential");

    List<CredentialVersion> versions = newArrayList(credentialVersion1, credentialVersion2);

    UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);

    when(permissionedCredentialService.findByUuid(eq(uuid), any()))
        .thenReturn(aCredential);
    when(certificateVersionDataService.findActiveWithTransitional("my-credential"))
        .thenReturn(versions);

    final List<CredentialVersion> certificates = subject.getVersions(uuid, true, newArrayList());
    assertThat(certificates, equalTo(versions));
  }

  @Test(expected = InvalidQueryParameterException.class)
  public void getVersions_returnsAnError_whenUUIDisInvalid() throws Exception {
    when(certificateVersionDataService.findAllVersions(uuid)).thenThrow(new IllegalArgumentException());
    subject.getVersions(uuid, false, newArrayList());
  }

  @Test(expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenCredentialListisEmpty() throws Exception {
    when(certificateVersionDataService.findAllVersions(uuid)).thenReturn(Collections.emptyList());
    subject.getVersions(uuid, false, newArrayList());
  }

  @Test (expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenUserDoesntHavePermission() throws Exception {
    CredentialVersion myCredential = mock(CredentialVersion.class);
    when(myCredential.getName()).thenReturn("my-credential");
    CredentialVersion secondVersion = mock(CredentialVersion.class);
    when(secondVersion.getName()).thenReturn("my-credential");

    List<CredentialVersion> versions = newArrayList(myCredential, secondVersion);

    UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(false);

    when(certificateVersionDataService.findAllVersions(uuid))
        .thenReturn(versions);

    subject.getVersions(uuid, false, newArrayList());

  }


}