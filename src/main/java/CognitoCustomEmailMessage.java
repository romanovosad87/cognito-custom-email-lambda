import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.services.simpleemail.model.Destination;
import com.amazonaws.services.simpleemail.model.SendTemplatedEmailRequest;
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

    public CognitoUserPoolCustomSenderEvent handleRequest(CognitoUserPoolCustomSenderEvent event,
                                                          Context context) {
        LambdaLogger logger = context.getLogger();
        logger.log("Trigger Source" + event.getTriggerSource());

        if (event.getTriggerSource().equals("CustomEmailSender_SignUp")) {
            if (event.getRequest().getCode() != null) {
                String code = event.getRequest().getCode();
                sendEmail(event, SUBJECT, code, TITLE_SIGN_UP);
            }
        } else if (event.getTriggerSource().equals("CustomEmailSender_ResendCode")) {
            if (event.getRequest().getCode() != null) {
                String code = event.getRequest().getCode();
                sendEmail(event, SUBJECT, code, TITLE_RESEND_CODE);
            }
        } else if (event.getTriggerSource().equals("CustomEmailSender_ForgotPassword")) {
            if (event.getRequest().getCode() != null) {
                String code = event.getRequest().getCode();
                sendEmail(event, SUBJECT, code, TITLE_FORGOT_PASSWORD);
            }
        } else if (event.getTriggerSource().equals("CustomEmailSender_UpdateUserAttribute")) {

        } else if (event.getTriggerSource().equals("CustomEmailSender_VerifyUserAttribute")) {

        } else if (event.getTriggerSource().equals("CustomEmailSender_AdminCreateUser")) {

        } else if (event.getTriggerSource().equals("CustomEmailSender_AccountTakeOverNotification")) {

        }
        return event;
    }

    public AmazonSimpleEmailService getAmazonSESClient() {
        final BasicAWSCredentials basicAWSCredentials = new BasicAWSCredentials(ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);

        return AmazonSimpleEmailServiceClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(basicAWSCredentials))
                .withRegion(REGION_NAME)
                .build();
    }

    public String decrypt(String encryptedVerificationCode) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                .build();

        // 2. Instantiate an AWS KMS master key provider in strict mode using buildStrict().
        final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder().buildStrict(KEY_ARN);

        // 3. Decrypt the data
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(keyProvider,
                Base64.getDecoder().decode(encryptedVerificationCode));
        byte[] result = decryptResult.getResult();
        return new String(result);
    }

    public void sendEmail(CognitoUserPoolCustomSenderEvent event, String subject, String code, String title) {
        SendTemplatedEmailRequest sendTemplatedEmailRequest = new SendTemplatedEmailRequest();
        String decryptedCode = decrypt(code);

        Destination destination = new Destination()
                .withToAddresses(event.getRequest()
                        .getUserAttributes().get("email"));

        sendTemplatedEmailRequest.setTemplate(AWS_SES_TEMPLATE);
        sendTemplatedEmailRequest.setTemplateData(String.format("{\"subject\":\"%s\", "
                + "\"code\":\"%s\", \"title\":\"%s\"}", subject, decryptedCode, title));
        sendTemplatedEmailRequest.setDestination(destination);
        sendTemplatedEmailRequest.setSource("Art vs War <no-reply@artvswar.gallery>");
        sendTemplatedEmailRequest.setReturnPath("info@artvswar.gallery");
        AmazonSimpleEmailService amazonSESClient = getAmazonSESClient();
        amazonSESClient.sendTemplatedEmail(sendTemplatedEmailRequest);
    }
}
