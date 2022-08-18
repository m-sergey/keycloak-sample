<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("customResetCredentialsTitle",realm.displayName)}
	<#elseif section = "form">
		<form id="kc-custom-reset-credentials-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
			    <!-- Username -->
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="username" class="${properties.kcLabelClass!}">${msg("usernameLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="text" id="username" name="username" class="${properties.kcInputClass!}" autofocus/>
				</div>
			    <!-- Secret answer -->
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="secretAnswer" class="${properties.kcLabelClass!}">${msg("answerQuestion")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="text" id="secretAnswer" name="secretAnswer" class="${properties.kcInputClass!}" />
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
					<input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("resetCredentialsPassword")}"/>
				</div>
			</div>
		</form>
	</#if>
</@layout.registrationLayout>
