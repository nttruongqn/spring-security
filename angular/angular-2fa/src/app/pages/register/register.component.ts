import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticationResponse } from 'src/app/models/authentication-response';
import { RegisterRequest } from 'src/app/models/register-request';
import { VerificationRequest } from 'src/app/models/verification-request';
import { AuthenticationService } from 'src/app/services/authentication.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent {
  registerRequest: RegisterRequest = {};
  authResponse: AuthenticationResponse = {};
  message = '';
  otpCode = '';

  constructor(private authService: AuthenticationService, private router: Router
  ) { }

  registerUser() {
    this.message = '';
    this.authService.register(this.registerRequest).subscribe({
      next: (response) => {
        if (response) {
          this.authResponse = response;
        } else {
          this.message = "Account create successfully\n Redirected to the Login Page in 3s";
          setTimeout(() => {
            this.router.navigate(['login'])
          }, 3000)
        }
      }
    })

  }

  verifyTfa() {
    this.message = '';
    const verifyRequest: VerificationRequest = {
      email: this.registerRequest.email,
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
