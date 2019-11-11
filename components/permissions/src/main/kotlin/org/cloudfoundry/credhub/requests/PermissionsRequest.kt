package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import javax.validation.constraints.NotEmpty
import org.apache.commons.lang3.StringUtils.prependIfMissing
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.cloudfoundry.credhub.ErrorMessages

@JsonAutoDetect
class PermissionsRequest {

    @NotEmpty(message = ErrorMessages.MISSING_NAME)
    var credentialName: String? = null
        set(credentialName) {
            if (!credentialName.isNullOrEmpty()) {
                field = prependIfMissing(credentialName, "/")
            }
        }
    @NotEmpty(message = ErrorMessages.Permissions.MISSING_ACES)
    var permissions: MutableList<PermissionEntry>? = null

    constructor() : super() {
        /* this needs to be there for jackson to be happy */
    }

    constructor(credentialName: String?, permissions: MutableList<PermissionEntry>?) : super() {
        this.credentialName = credentialName
        this.permissions = permissions
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as PermissionsRequest?

        return EqualsBuilder()
            .append(credentialName, that!!.credentialName)
            .append(permissions, that.permissions)
            .isEquals
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(17, 37)
            .append(credentialName)
            .append(permissions)
            .toHashCode()
    }
}
