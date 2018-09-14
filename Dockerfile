FROM jboss/keycloak:4.4.0.Final
ADD jdsmart/target/keycloak-social-providers-jdsmart-1.0.0-SNAPSHOT.jar /opt/jboss/keycloak/providers/
ADD wechat/target/keycloak-social-providers-wechat-1.0.0-SNAPSHOT.jar /opt/jboss/keycloak/providers/
ADD templates/ /opt/jboss/keycloak/themes/base/admin/resources/partials/
ADD messages/ /opt/jboss/keycloak/themes/base/admin/messages/