<?php
/**
 *  Class to Scan Websites for Malware, Updates, Added or Removed Files
 */

class Mailer {

  public static function mail($site_name, $htmlbody) {
    $mail = new PHPMailer;

    $mail->isSMTP();                                      // Set mailer to use SMTP
    $mail->Host = SMTPHOST;  // Specify main and backup SMTP servers
    $mail->SMTPAuth = SMTPAuth;                               // Enable SMTP authentication
    $mail->Username = SMTPUsername;                 // SMTP username
    $mail->Password = SMTPPassword;                           // SMTP password
    $mail->SMTPSecure = SMTPSecure;                            // Enable TLS encryption, `ssl` also accepted
    $mail->Port = SMTPPort;                                    // TCP port to connect to

    $mail->setFrom(FROM_EMAIL, ''.$site_name.' Scan');
    $mail->addAddress(EMAIL_ALERT);     // Add a recipient

    $mail->isHTML(true);                                  // Set email format to HTML

    $mail->Subject = ''.$site_name.' Scan';
    $mail->Body    = $htmlbody;

    if(!$mail->send()) {
        return 'Message could not be sent.';
        return 'Mailer Error: ' . $mail->ErrorInfo;
    } else {
        return 'Message has been sent';
    }
  }

}
