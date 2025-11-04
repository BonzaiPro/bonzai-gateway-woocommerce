<?php
/*
Plugin Name: Bonzai Payment Gateway
Description: Paiement via Bonzai Checkout avec webhooks de confirmation.
Version: 1.3.0
Author: Ramy
*/

if (!defined('ABSPATH')) exit;

add_action('plugins_loaded', 'bonzai_init_gateway_class');

function bonzai_init_gateway_class() {

    class WC_Gateway_Bonzai extends WC_Payment_Gateway {

        /** @var WC_Logger|null */
        protected $logger = null;

        public function __construct() {
            $this->id                 = 'bonzai';
            $this->icon               = ''; // URL logo si besoin
            $this->has_fields         = false;
            $this->method_title       = 'Bonzai';
            $this->method_description = 'Payer via Bonzai Checkout.';
            $this->supports           = array('products');

            $this->init_form_fields();
            $this->init_settings();

            // Settings
            $this->title          = $this->get_option('title');
            $this->description    = $this->get_option('description');
            $this->enabled        = $this->get_option('enabled');
            $this->api_token      = trim($this->get_option('api_token'));
            $this->redirect_url   = trim($this->get_option('redirect_url'));
            $this->debug          = wc_string_to_bool($this->get_option('debug', 'no'));
            $this->timeout        = absint($this->get_option('timeout', 20));
            $this->force_currency = strtoupper(trim($this->get_option('force_currency', ''))); // '', EUR, USD
            $this->min_amount     = floatval($this->get_option('min_amount', 0));

            // Webhook token uniquement (pas de signature chez Bonzai)
            $this->webhook_token  = trim($this->get_option('webhook_token', ''));

            if ($this->debug) {
                $this->logger = wc_get_logger();
            }

            add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
        }

        public function init_form_fields() {
            $this->form_fields = array(
                'enabled' => array(
                    'title'   => 'Activer',
                    'type'    => 'checkbox',
                    'label'   => 'Activer Bonzai Checkout',
                    'default' => 'yes',
                ),
                'title' => array(
                    'title'       => 'Titre',
                    'type'        => 'text',
                    'description' => 'Texte affiché au checkout.',
                    'default'     => 'Payer avec Bonzai',
                ),
                'description' => array(
                    'title'       => 'Description',
                    'type'        => 'textarea',
                    'default'     => 'Vous serez redirigé vers Bonzai pour finaliser le paiement.',
                ),
                'api_token' => array(
                    'title'       => 'API Token',
                    'type'        => 'password',
                    'description' => 'Token API Bonzai (profil Bonzai -> Gérer les jetons API).',
                ),
                'redirect_url' => array(
                    'title'       => 'Redirect URL après paiement',
                    'type'        => 'text',
                    'default'     => home_url('/merci'),
                ),
                'force_currency' => array(
                    'title'       => 'Devise envoyée à Bonzai',
                    'type'        => 'select',
                    'description' => 'Si vide, on envoie la devise Woo. Bonzai accepte EUR ou USD.',
                    'default'     => '',
                    'options'     => array(
                        ''    => 'Utiliser la devise Woo',
                        'EUR' => 'Forcer EUR',
                        'USD' => 'Forcer USD',
                    ),
                ),
                'min_amount' => array(
                    'title'       => 'Montant minimum',
                    'type'        => 'number',
                    'description' => 'Seuil minimum pour afficher la passerelle. 0 pour désactiver.',
                    'default'     => '0',
                    'custom_attributes' => array('step' => '0.01', 'min' => '0'),
                ),
                'timeout' => array(
                    'title'       => 'Délai requête API (secondes)',
                    'type'        => 'number',
                    'default'     => '20',
                    'custom_attributes' => array('min' => '5', 'step' => '1'),
                ),
                'debug' => array(
                    'title'       => 'Logs debug',
                    'type'        => 'checkbox',
                    'label'       => 'Activer les logs (WooCommerce -> Statut -> Journaux)',
                    'default'     => 'no',
                ),

                // Webhooks Bonzai
                'webhook_title' => array(
                    'title'       => 'Webhooks Bonzai',
                    'type'        => 'title',
                    'description' => 'Bonzai envoie 2 événements: product_access_granted et product_access_revoked. Sécurité par token uniquement.',
                ),
                'webhook_token' => array(
                    'title'       => 'Webhook Token',
                    'type'        => 'text',
                    'description' => 'Obligatoire. Le webhook doit inclure ce token en query (?token=...) ou dans l’entête X-Bonzai-Token.',
                ),
                'webhook_url' => array(
                    'title'       => 'Webhook URL',
                    'type'        => 'title',
                    'description' => '<code>' . esc_html(rest_url('bonzai/v1/webhook') . '?token=VOTRE_TOKEN') . '</code>',
                ),
            );
        }

        public function is_available() {
            if ('yes' !== $this->enabled) return false;
            if (empty($this->api_token)) return false;

            $currency = get_woocommerce_currency();
            $target   = $this->force_currency ? $this->force_currency : $currency;
            if (!in_array($target, array('EUR', 'USD'), true)) return false;

            if (function_exists('WC') && WC()->cart) {
                $total = floatval(WC()->cart->total);
                if ($this->min_amount > 0 && $total < $this->min_amount) return false;
            }
            return parent::is_available();
        }

        protected function log($message, $context = array()) {
            if ($this->logger) {
                $this->logger->info('[Bonzai] ' . $message, array('source' => 'bonzai-gateway') + $context);
            }
        }

        protected function get_product_uuid_from_order(WC_Order $order) {
            foreach ($order->get_items() as $item) {
                if (!is_a($item, 'WC_Order_Item_Product')) continue;
                $pid = $item->get_product_id();
                if (!$pid) continue;
                $uuid = get_post_meta($pid, 'bonzai_product_uuid', true);
                if (!empty($uuid)) return $uuid;
            }
            return null;
        }

        protected function fail_with_notice(WC_Order $order, $msg) {
            wc_add_notice($msg, 'error');
            if ($order && is_a($order, 'WC_Order')) {
                $order->add_order_note('Bonzai: ' . $msg);
            }
            $this->log('Erreur: ' . $msg);
            return array('result' => 'fail');
        }

        public function process_payment($order_id) {
            $order = wc_get_order($order_id);
            if (!$order) return array('result' => 'fail');

            if (empty($this->api_token)) {
                return $this->fail_with_notice($order, 'Token API Bonzai manquant dans WooCommerce -> Paiements -> Bonzai -> Gérer.');
            }

            $product_uuid = $this->get_product_uuid_from_order($order);
            if (!$product_uuid) {
                return $this->fail_with_notice($order, 'Produit Bonzai non configuré. Ajoute le champ "bonzai_product_uuid" sur le produit.');
            }

            $amount = (float) $order->get_total();
            if ($amount <= 0) {
                return $this->fail_with_notice($order, 'Montant invalide pour la commande.');
            }

            $currency = $this->force_currency ? $this->force_currency : get_woocommerce_currency();
            if (!in_array($currency, array('EUR', 'USD'), true)) $currency = 'EUR';

            $email        = $order->get_billing_email() ?: '';
            $redirect_url = $this->redirect_url ?: home_url('/merci');
            $redirect_url = add_query_arg(array('wc_order' => $order->get_id()), $redirect_url);

            $payload = array(
                'amount'       => round($amount, 2),
                'currency'     => $currency,
                'title'        => 'Commande Woo #' . $order->get_id(),
                'redirect_url' => $redirect_url,
                'metadata'     => array(
                    'wc_order_id' => $order->get_id(),
                    'site'        => home_url(),
                ),
                'is_vat_incl'  => true,
                'mode'         => 'one_off',
            );
            if (!empty($email)) $payload['email'] = sanitize_email($email);

            $this->log('Appel checkout Bonzai: ' . wp_json_encode($payload));

            $response = wp_remote_post("https://www.bonzai.pro/api/v1/products/$product_uuid/checkout", array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_token,
                    'Content-Type'  => 'application/json',
                ),
                'body'    => wp_json_encode($payload),
                'timeout' => max(5, $this->timeout),
            ));

            if (is_wp_error($response)) {
                return $this->fail_with_notice($order, 'Erreur API Bonzai: ' . $response->get_error_message());
            }

            $code_http = (int) wp_remote_retrieve_response_code($response);
            $body_txt  = wp_remote_retrieve_body($response);
            $body      = json_decode($body_txt, true);

            if ($code_http !== 200 || empty($body['checkout_url'])) {
                $order->add_order_note('Bonzai API ' . $code_http . ' -> ' . $body_txt);
                return $this->fail_with_notice($order, 'Impossible de créer le paiement Bonzai. Réessaye plus tard.');
            }

            $order->update_status('pending', 'En attente de paiement Bonzai.');
            $order->add_order_note('Redirection vers Bonzai. Bonzai order_id: ' . ($body['order_id'] ?? 'n/a'));

            $this->log('Redirection vers checkout_url: ' . $body['checkout_url']);
            
            // Sauvegarder l'order_id Bonzai pour le mapping webhook
            if (!empty($body['order_id'])) {
                update_post_meta($order->get_id(), '_bonzai_order_id', sanitize_text_field($body['order_id']));
                $order->add_order_note('Bonzai: order_id associé ' . $body['order_id']);
            }

            return array(
                'result'   => 'success',
                'redirect' => esc_url_raw($body['checkout_url']),
            );
        }
    }
}

// Enregistre la passerelle
add_filter('woocommerce_payment_gateways', function($methods){
    $methods[] = 'WC_Gateway_Bonzai';
    return $methods;
});


/* =======================
   Webhook Bonzai -> Woo
   ======================= */

add_action('rest_api_init', function () {
    register_rest_route('bonzai/v1', '/webhook', array(
        'methods'             => 'POST',
        'callback'            => 'bonzai_handle_webhook',
        'permission_callback' => '__return_true',
    ));
});

function bonzai_get_gateway_instance() {
    if (!function_exists('WC') || !WC()->payment_gateways()) return null;
    $gws = WC()->payment_gateways()->payment_gateways();
    return isset($gws['bonzai']) ? $gws['bonzai'] : null;
}

/** Vérifie le token: query ?token=... OU entête X-Bonzai-Token */
function bonzai_verify_token(WP_REST_Request $request, $gateway) {
    $configured = trim($gateway->get_option('webhook_token'));
    if ($configured === '') return false; // exigé pour éviter les appels anonymes
    $q = (string) $request->get_param('token');
    $h = (string) $request->get_header('x-bonzai-token');
    return hash_equals($configured, $q) || hash_equals($configured, $h);
}

/** Idempotence simple */
function bonzai_already_processed($event_id) {
    if (!$event_id) return false;
    $key = 'bonz_evt_' . md5($event_id);
    if (get_transient($key)) return true;
    set_transient($key, 1, DAY_IN_SECONDS);
    return false;
}

/** Trouve la commande via order.metadata.wc_order_id */
function bonzai_find_wc_order_from_payload(array $evt) {
    // 1) Normal : via metadata.wc_order_id (quand présent)
    $wc_id = $evt['order']['metadata']['wc_order_id'] ?? null;
    if ($wc_id) {
        $order = wc_get_order((int) $wc_id);
        if ($order) return $order;
    }

    // 2) Mapping via order_id Bonzai précédemment stocké en meta
    $bonzai_order_id = $evt['order_id'] ?? ($evt['order']['id'] ?? null);
    if (!empty($bonzai_order_id)) {
        $orders = wc_get_orders(array(
            'limit'      => 1,
            'meta_key'   => '_bonzai_order_id',
            'meta_value' => (string) $bonzai_order_id,
            'return'     => 'objects',
        ));
        if (!empty($orders)) return $orders[0];
    }

    // 3) Fallback par email (utile si test Bonzai sans metadata)
    $email = $evt['user']['email'] ?? '';
    if ($email !== '') {
        $orders = wc_get_orders(array(
            'limit'         => 1,
            'orderby'       => 'date',
            'order'         => 'DESC',
            'status'        => array('pending','on-hold'),
            'billing_email' => $email,
            'return'        => 'objects',
        ));
        if (!empty($orders)) return $orders[0];
    }

    return null;
}

/** Handler Webhook suivant la doc Bonzai */
function bonzai_handle_webhook(WP_REST_Request $request) {
    $gw = bonzai_get_gateway_instance();
    if (!$gw) return new WP_REST_Response(array('ok'=>false,'msg'=>'gateway not loaded'), 503);

    if (!bonzai_verify_token($request, $gw)) {
        return new WP_REST_Response(array('ok'=>false,'msg'=>'invalid token'), 401);
    }

    $raw = $request->get_body();
    $evt = json_decode($raw, true);
    if (!is_array($evt)) {
        return new WP_REST_Response(array('ok'=>false,'msg'=>'invalid json'), 400);
    }

    // Un id stable pour l’idempotence
    $event_id = $evt['id'] ?? $evt['order_id'] ?? $evt['timestamp'] ?? hash('sha256', $raw);
    if (bonzai_already_processed($event_id)) {
        return new WP_REST_Response(array('ok'=>true,'msg'=>'duplicate'), 200);
    }

    $type  = $evt['event_type'] ?? 'unknown'; // product_access_granted / product_access_revoked
    $order = bonzai_find_wc_order_from_payload($evt);

    if (!$order) {
        if (function_exists('wc_get_logger')) {
            wc_get_logger()->warning('[Bonzai] Webhook sans wc_order_id (metadata null) : ' . $raw, array('source'=>'bonzai-gateway'));
        }
        return new WP_REST_Response(array('ok'=>true,'msg'=>'no wc order'), 200);
    }

    switch ($type) {
        case 'product_access_granted':
            if (!$order->is_paid()) {
                $order->payment_complete();
                $order->add_order_note('Bonzai: product_access_granted -> paiement confirmé.');
            }
            break;

        case 'product_access_revoked':
            // Choix fonctionnel: refunded par défaut. Mets 'cancelled' si tu préfères.
            $target = 'refunded';
            if ($order->get_status() !== $target) {
                $order->update_status($target, 'Bonzai: product_access_revoked.');
            }
            break;

        default:
            $order->add_order_note('Bonzai: événement non géré ' . esc_html($type) . '.');
            break;
    }

    return new WP_REST_Response(array('ok'=>true), 200);
}

// Note informative sur la page de retour si le webhook n’est pas encore arrivé
add_action('template_redirect', function(){
    if (!isset($_GET['wc_order'])) return;
    $order = wc_get_order(absint($_GET['wc_order']));
    if (!$order || $order->is_paid()) return;
    $order->add_order_note('Client revenu sur la page de retour. En attente du webhook Bonzai.');
});

// Forcer le statut "completed" quand le paiement est confirmé par Bonzai
add_filter('woocommerce_payment_complete_order_status', function($status, $order_id, $order){
    if ($order instanceof WC_Order && $order->get_payment_method() === 'bonzai') {
        return 'completed';
    }
    return $status;
}, 10, 3);
