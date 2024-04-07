import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.services.simpleemail.model.Destination;
import com.amazonaws.services.simpleemail.model.SendTemplatedEmailRequest;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import java.util.Base64;

public class CognitoCustomEmailMessage {

    private static final String ACCESS_KEY_ID = System.getenv("AWS_SES_ACCESS_KEY_ID");
    private static final String ACCESS_KEY_SECRET = System.getenv("AWS_SES_ACCESS_KEY_SECRET");
    private static final String REGION_NAME = System.getenv("REGION");
    private static final String KEY_ARN = System.getenv("KEY_ARN");
    private static final String TITLE_SIGN_UP = "Confirm your email address";
    private static final String TITLE_FORGOT_PASSWORD = "Reset password request";
    private static final String TITLE_RESEND_CODE = "Resend code request";
    private static final String SUBJECT = "Confirmation code";
    public static final String AWS_SES_TEMPLATE = "Confirmation_Code-1705094828937";
    public static final String EMAIL = "email";
    public static final String SOURCE = "";
    public static final String RETURN_PATH = "";
    public static final String CUSTOM_EMAIL_SENDER_SIGN_UP = "CustomEmailSender_SignUp";
    public static final String CUSTOM_EMAIL_SENDER_RESEND_CODE = "CustomEmailSender_ResendCode";
    public static final String CUSTOM_EMAIL_SENDER_FORGOT_PASSWORD = "CustomEmailSender_ForgotPassword";

    public CognitoUserPoolCustomSenderEvent handleRequest(CognitoUserPoolCustomSenderEvent event,
                                                          Context context) {
        LambdaLogger logger = context.getLogger();
        String triggerSource = event.getTriggerSource();
        logger.log("Trigger Source" + triggerSource);

        String code = event.getRequest().getCode();
        if (triggerSource.equals(CUSTOM_EMAIL_SENDER_SIGN_UP) && code != null) {
            sendEmail(event, SUBJECT, code, TITLE_SIGN_UP);
        } else if (triggerSource.equals(CUSTOM_EMAIL_SENDER_RESEND_CODE) && code != null) {
            sendEmail(event, SUBJECT, code, TITLE_RESEND_CODE);
        } else if (triggerSource.equals(CUSTOM_EMAIL_SENDER_FORGOT_PASSWORD) && code != null) {
            sendEmail(event, SUBJECT, code, TITLE_FORGOT_PASSWORD);
        }
        return event;
    }

    private AmazonSimpleEmailService getAmazonSESClient() {
        final BasicAWSCredentials basicAWSCredentials = new BasicAWSCredentials(ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);

        return AmazonSimpleEmailServiceClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(basicAWSCredentials))
                .withRegion(REGION_NAME)
                .build();
    }

    private String decrypt(String encryptedCode) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                .build();

        // 2. Create the AWS KMS keyring.
        // We create a multi keyring, as this interface creates the KMS client for us automatically.
        final MaterialProviders materialProviders = MaterialProviders.builder()
                .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                .build();
        final CreateAwsKmsMultiKeyringInput keyringInput =
                CreateAwsKmsMultiKeyringInput.builder().generator(KEY_ARN).build();
        final IKeyring kmsKeyring = materialProviders.CreateAwsKmsMultiKeyring(keyringInput);

        // 3. Decrypt the data
        final CryptoResult<byte[], ?> decryptResult =
                crypto.decryptData(
                        kmsKeyring, Base64.getDecoder().decode(encryptedCode));
        byte[] result = decryptResult.getResult();
        return new String(result);
    }

    private void sendEmail(CognitoUserPoolCustomSenderEvent event, String subject, String code,
                          String title) {
        SendTemplatedEmailRequest sendTemplatedEmailRequest = new SendTemplatedEmailRequest();
        String decryptedCode = decrypt(code);

        Destination destination = new Destination()
                .withToAddresses(event.getRequest()
                        .getUserAttributes().get(EMAIL));

        sendTemplatedEmailRequest.setTemplate(AWS_SES_TEMPLATE);
        sendTemplatedEmailRequest.setTemplateData(String.format("{\"subject\":\"%s\", "
                + "\"code\":\"%s\", \"title\":\"%s\"}", subject, decryptedCode, title));
        sendTemplatedEmailRequest.setDestination(destination);
        sendTemplatedEmailRequest.setSource(SOURCE);
        sendTemplatedEmailRequest.setReturnPath(RETURN_PATH);
        AmazonSimpleEmailService amazonSESClient = getAmazonSESClient();
        amazonSESClient.sendTemplatedEmail(sendTemplatedEmailRequest);
    }
}
