package org.cloudfoundry.credhub.controllers.autodocs.v1.credentials

import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.testdoubles.SetHandler
import org.cloudfoundry.credhub.views.CredentialView

class SpySetHandler : SetHandler {
    lateinit var handle_calledWithSetRequest: BaseCredentialSetRequest<*>
    lateinit var handle_returnsCredentialView: CredentialView
    override fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        handle_calledWithSetRequest = setRequest
        return handle_returnsCredentialView
    }
}