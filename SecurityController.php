<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\ChangePasswordType;
use App\Form\ResetPasswordType;
use App\Form\UpdatePasswordType;
use App\Model\UserInterface;
use App\Service\Contracts\Security\SecurityManagerInterface;
use App\Service\Contracts\MailerInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use LogicException;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Validator\Constraints\Email;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Contracts\Translation\TranslatorInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

class SecurityController extends AbstractController
{

    const PKCE_TOKEN_DATA_KEY='pkce_token_data';
    const TARGET_PATH_KEY='target_path';

    /**
     * @var FirewallMap
     */
    protected $firewallMap;
    private $logger;

    public function __construct(
        FirewallMap $firewallMap,
        LoggerInterface $logger
    ) {
        $this->firewallMap = $firewallMap;
        $this->logger = $logger;
    }
    /**
     * @Route("/login", name="app_login")
     */
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        $user = $this->getUser();
        if ($user) {
            $this->logger->debug('Utente già autenticato, redirect alla root', ['user_id' => $user->getId()]);
            return $this->redirect('/');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        $this->logger->debug('Mostro form login', ['last_username' => $lastUsername]);

        return $this->render('@EasyAdmin/page/login.html.twig', [
            'page_title' => '<img src="/images/logo.png">',
            'last_username' => $lastUsername,
            'error' => $error,
            'csrf_token_intention' => 'authenticate',
            'username_parameter' => 'email',
            'password_parameter' => 'password',
            'action' => $this->generateUrl('app_login_check'),
            'pkce_enabled' => true
        ]);
    }

    /**
     * Login con PKCE - valida credenziali e parametri PKCE
     * @Route("/login-check", name="app_login_check", methods={"POST"})
     */
    public function loginCheck(
        Request $request,
        EntityManagerInterface $entityManager,
        PasswordHasherFactoryInterface $passwordHasherFactory,
        SessionInterface $session
    ): Response {
        if ($this->getUser()) {
            $this->logger->debug('LoginCheck chiamato ma utente già autenticato');
            return $this->redirect('/');
        }

        $email = $request->request->get('email');
        $password = $request->request->get('password');
        $codeChallenge = $request->query->get('code_challenge');
        $codeVerifier = $request->query->get('code_verifier');
        $targetPath = $request->request->get('_target_path', '/');

        $this->logger->debug('LoginCheck parametri ricevuti', [
            'email' => $email,
            'code_challenge' => $codeChallenge,
            'target_path' => $targetPath
        ]);

        if (!$email || !$password) {
            $this->addFlash('danger', 'Email e password obbligatorie');
            $this->logger->warning('Email o password mancanti', ['email' => $email]);
            return $this->redirectToRoute('app_login');
        }

        if (!$codeChallenge || !$codeVerifier) {
            $this->addFlash('danger', 'Parametri di sicurezza non validi');
            $this->logger->warning('PKCE non valido', [
                'code_challenge' => $codeChallenge,
                'code_verifier' => $codeVerifier
            ]);
            return $this->redirectToRoute('app_login');
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user) {
            $this->addFlash('danger', 'Credenziali non valide');
            $this->logger->warning('Utente non trovato per email', ['email' => $email]);
            return $this->redirectToRoute('app_login');
        }

        $passwordHasher = $passwordHasherFactory->getPasswordHasher($user);
        if (!$passwordHasher->verify($user->getPassword(), $password)) {
            $this->addFlash('danger', 'Credenziali non valide');
            $this->logger->warning('Password non valida', ['user_id' => $user->getId()]);
            return $this->redirectToRoute('app_login');
        }

        $computedChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        if ($computedChallenge !== $codeChallenge) {
            $this->addFlash('danger', 'Verifica di sicurezza fallita');
            $this->logger->warning('PKCE challenge mismatch', [
                'computed' => $computedChallenge,
                'received' => $codeChallenge
            ]);
            return $this->redirectToRoute('app_login');
        }

        $authorizationCode = bin2hex(random_bytes(32));

        $session->set('pkce_token_data', [
            'authorization_code' => $authorizationCode,
            'code_challenge' => $codeChallenge,
            'code_verifier' => $codeVerifier,
            'user_id' => $user->getId(),
            'target_path' => $targetPath,
            'timestamp' => time()
        ]);

        $this->logger->info('PKCE validato, creato authorization code', [
            'authorization_code' => $authorizationCode,
            'user_id' => $user->getId()
        ]);

        return $this->render('security/pkce_token_exchange.html.twig', [
            'page_title' => '<img src="/images/logo.png">',
            'authorization_code' => $authorizationCode,
            'code_verifier' => $codeVerifier,
            'token_url' => $this->generateUrl('pkce_token')
        ]);
    }

    /**
     * PKCE Token - passo finale che completa l'autenticazione
     * @Route("/pkce/token", name="pkce_token", methods={"POST"})
     */
    public function pkceToken(
        Request $request,
        SessionInterface $session,
        EntityManagerInterface $entityManager,
        TokenStorageInterface $tokenStorage
    ): Response {
        $tokenData = $session->get('pkce_token_data');

        if (!$tokenData || (time() - $tokenData['timestamp']) > 300) {
            $session->remove('pkce_token_data');
            $this->logger->warning('PKCE sessione scaduta o mancante');
            return new JsonResponse(['error' => 'Token sessione scaduta'], 400);
        }

        $authorizationCode = $request->request->get('authorization_code');
        $codeVerifier = $request->request->get('code_verifier');

        $this->logger->debug('pkceToken ricevuti', [
            'authorization_code' => $authorizationCode,
            'code_verifier' => $codeVerifier
        ]);

        if (!$authorizationCode || !$codeVerifier) {
            return new JsonResponse(['error' => 'Parametri mancanti'], 400);
        }

        if ($authorizationCode !== $tokenData['authorization_code']) {
            $session->remove('pkce_token_data');
            $this->logger->warning('Authorization code non valido', ['received' => $authorizationCode]);
            return new JsonResponse(['error' => 'Authorization code non valido'], 400);
        }

        $computedChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        if ($computedChallenge !== $tokenData['code_challenge']) {
            $session->remove('pkce_token_data');
            $this->logger->warning('PKCE challenge mismatch in token exchange', [
                'computed' => $computedChallenge,
                'expected' => $tokenData['code_challenge']
            ]);
            return new JsonResponse(['error' => 'Verifica PKCE fallita'], 400);
        }

        $user = $entityManager->getRepository(User::class)->find($tokenData['user_id']);
        if (!$user) {
            $session->remove('pkce_token_data');
            $this->logger->error('Utente non trovato durante scambio PKCE', ['user_id' => $tokenData['user_id']]);
            return new JsonResponse(['error' => 'Utente non trovato'], 400);
        }

        $token = new UsernamePasswordToken($user, 'main', $user->getRoles());
        $tokenStorage->setToken($token);
        $session->set('_security_main', serialize($token));
        $session->migrate(true);
        $session->remove('pkce_token_data');

        $targetPath = $tokenData['target_path'] ?? '/';

        $this->logger->info('Utente autenticato tramite PKCE', [
            'user_id' => $user->getId(),
            'redirect_url' => $targetPath
        ]);

        return new JsonResponse([
            'success' => true,
            'redirect_url' => $targetPath
        ]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new LogicException('Questo metodo può essere vuoto, gestito dal firewall.');
    }

    /**
     * @Route("/update-password/{token}", name="security_update_password")
     */
    public function updatePassword(
        EntityManagerInterface         $entityManager,
        Request                        $request,
        TokenStorageInterface          $tokenStorage,
        EventDispatcherInterface       $eventDispatcher,
        SessionInterface               $session,
        PasswordHasherFactoryInterface $passwordHasherFactory,
        TranslatorInterface            $translator,
                                       $token
    ) {
        $user = $entityManager->getRepository(User::class)->findOneBy(['updatePasswordToken' => $token]);

        if (!$user) {
            throw $this->createNotFoundException();
        }

        $form = $this->createForm(UpdatePasswordType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $user->setUpdatePasswordToken(null);
            $passwordHasher = $passwordHasherFactory->getPasswordHasher($user);
            $user->setPassword($passwordHasher->hash($user->getPlainPassword(), $user->getSalt()));

            $entityManager->flush();

            $targetPath = '/';

            if (($firewallConfig = $this->firewallMap->getFirewallConfig($request)) &&
                $firewallConfig->getName()) {
                $targetPath = $session->get(implode('.', ['_security', $firewallConfig->getName(), self::TARGET_PATH_KEY]), $targetPath);
            }

            $this->addFlash('success', $translator->trans('flash_messages.update_password.success'));

            return $this->redirect($targetPath ?? '/');
        }

        return $this->render('security/update_password.html.twig', [
            'form' => $form->createView(),
            'page_title' => '<img src="/images/logo.png"/>'
        ]);
    }

    /**
     * @Route(path="/change-password", name="security_change_password")
     */
    public function changePassword(
        Request                         $request,
        TokenStorageInterface           $tokenStorage,
        EntityManagerInterface          $entityManager,
        SecurityManagerInterface        $securityManager,
        TranslatorInterface             $translator,
    ): Response
    {
        /** @var UserInterface $user */
        $user = $tokenStorage->getToken()->getUser();

        $form = $this->createForm(ChangePasswordType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $securityManager->resetUserPassword($user);

            $entityManager->flush();
            $this->addFlash('success', $translator->trans('flash_messages.update_password.success'));
            return $this->redirectToRoute('admin');
        }

        return $this->render('security/change_password.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     * @Route(path="/reset-password/request", name="security_reset_password_request")
     */
    public function requestResetPassword(
        SecurityManagerInterface $securityManager,
        TranslatorInterface $translator,
        MailerInterface $mailer,
        Request $request
    ): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('admin');
        }

        $form = $this->createFormBuilder()
            ->add('email', EmailType::class, [
                'required' => true,
                'label' => false,
                'attr' => [
                    'placeholder' => 'Email'
                ],
                'row_attr' => [
                    'class' => 'form-widget'
                ],
                'constraints' => [
                    new NotBlank(),
                    new Email(),
                ],
            ])
            ->add('submit', SubmitType::class, [
                'label' => 'security.form.reset_password_request.submit',
                'attr' => [
                    'class' => 'btn btn-primary btn-lg btn-block'
                ],
                'row_attr' => [
                    'class' => 'submit'
                ]
            ])
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $email = $form->get('email')->getData();

            $user = $securityManager->loadUser($email);

            if (!$user) {
                $this->addFlash(
                    'success',
                    $translator->trans('flash_messages.reset_password_request.success', [
                        'login_url' => $this->generateUrl('app_login')
                    ])
                );
            } else {
                try {
                    $securityManager->prepareUserForResetPassword($user);
                } catch (LogicException $e) {
                    $this->addFlash('error', $e->getMessage());
                    return $this->redirect($this->generateUrl('security_reset_password_request'));
                }
                $mailer->sendResetPasswordEmail($user);
                $this->addFlash(
                    'success',
                    $translator->trans('flash_messages.reset_password_request.success', [
                        'login_url' => $this->generateUrl('app_login')
                    ])
                );
                return $this->redirect($this->generateUrl('security_reset_password_request'));
            }
        }

        return $this->render('security/request_reset_password.html.twig', [
            'form' => $form->createView(),
            'page_title' => '<img src="/images/logo.png"/>'
        ]);
    }

    /**
     * @Route(path="/reset-password/reset/{token}", name="security_reset_password_reset")
     */
    public function resetPassword(
        TranslatorInterface $translator,
        SecurityManagerInterface $securityManager,
        ManagerRegistry $managerRegistry,
        Request $request,
        $token
    ) {
        if ($this->getUser()) {
            return $this->redirectToRoute('admin');
        }

        $user = $managerRegistry->getRepository(User::class)->findOneBy([
            'resetPasswordToken' => $token
        ]);

        if (!$user) {
            throw $this->createNotFoundException($translator->trans('security.exception.reset_password_token_not_found'));
        }

        $form = $this->createForm(ResetPasswordType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $securityManager->resetUserPassword($user);

            $this->addFlash('success', $translator->trans('flash_messages.reset_password_reset.success'));

            return $this->redirect($this->generateUrl('app_login'));
        }

        return $this->render('security/reset_password.html.twig', [
            'form' => $form->createView(),
            'page_title' => '<img src="/images/logo.png"/>'
        ]);
    }
}
