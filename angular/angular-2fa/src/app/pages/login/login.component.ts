import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticationRequest } from 'src/app/models/authentication-request';
import { AuthenticationResponse } from 'src/app/models/authentication-response';
import { VerificationRequest } from 'src/app/models/verification-request';
import { AuthenticationService } from 'src/app/services/authentication.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent {
  authRequest: AuthenticationRequest = {};
  otpCode = '';
  authResponse: AuthenticationResponse = {};
  message = '';

  constructor(
    private authService: AuthenticationService,
    private router: Router
  ) {}

  authenticate() {
    this.authService.login(this.authRequest).subscribe(
      {
        next: (response) => {
          this.authResponse = response;
          if(!this.authResponse.mfaEnabled) {
            localStorage.setItem('token', response.accessToken as string);
            this.router.navigate(['welcome']);
          }
        }
      }
    )
  }

  verifyCode() {
    this.message = '';
    const verifyRequest: VerificationRequest = {
      email: this.authRequest.email,
      code: this.otpCode
    };
    this.authService.verifyCode(verifyRequest).subscribe({
      next: (response) => {
        this.message = "Account create successfully\n Redirected to the Welcome Page in 3s"
        setTimeout(() => {
          localStorage.setItem('token', response.accessToken as string);
          this.router.navigate(['welcome'])
        }, 3000)
      }
    })
  }

}
