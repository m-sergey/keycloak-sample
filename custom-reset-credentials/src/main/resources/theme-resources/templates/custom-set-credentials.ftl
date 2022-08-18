<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("customResetCredentialsTitle",realm.displayName)}
	<#elseif section = "form">
		<form id="kc-custom-reset-credentials-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
			    <!-- Current password -->
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="currentPassword" class="${properties.kcLabelClass!}">${msg("setCredentialsCurrentPassword")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="password" id="currentPassword" name="currentPassword" class="${properties.kcInputClass!}" autofocus/>
				</div>
				<!-- New password -->
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="newPassword" class="${properties.kcLabelClass!}">${msg("setCredentialsNewPassword")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="password" id="newPassword" name="newPassword" class="${properties.kcInputClass!}"/>
				</div>
			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
					<div class="${properties.kcFormOptionsWrapperClass!}">
						<span><a href="${url.loginUrl}">${kcSanitize(msg("backToLogin"))}</a></span>
					</div>
				</div>

				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("submitCredentialsNewPassword")}"/>
				</div>
			</div>
		</form>
	</#if>
</@layout.registrationLayout>
