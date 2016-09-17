package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedSecret;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

public class FindResults {
  private List<Credential> credentials;
  @SuppressWarnings("rawtypes")

  FindResults(List<Credential> credentials) {
    this.credentials = credentials;
  }
  public static FindResults fromEntity(List<NamedSecret> secrets) {
    List<Credential> credentials = newArrayList();
    for(NamedSecret s: secrets) {
      credentials.add(new Credential(s.getName(), s.getUpdatedAt()));
    }
    return new FindResults(credentials);
  }

  @JsonProperty
  public List<Credential> getCredentials() {
    return credentials;
  }
}
