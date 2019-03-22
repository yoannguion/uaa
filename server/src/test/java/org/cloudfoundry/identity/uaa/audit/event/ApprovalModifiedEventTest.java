package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Test;

public class ApprovalModifiedEventTest {

    @Test(expected = IllegalArgumentException.class)
    public void testRaisesWithBadSource() throws Exception {
        new ApprovalModifiedEvent(new Object(), new MockAuthentication(), IdentityZoneHolder.get());
    }

    @Test
    public void testAuditEvent() throws Exception {
        Approval approval = new Approval()
            .setUserId("mruser")
            .setClientId("app")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(1000))
            .setStatus(Approval.ApprovalStatus.APPROVED);

        ApprovalModifiedEvent event = new ApprovalModifiedEvent(approval, null, IdentityZoneHolder.get());

        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", auditEvent.getData());
        Assert.assertEquals(AuditEventType.ApprovalModifiedEvent, auditEvent.getType());
    }
}
