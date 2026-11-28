<?php
$databases['default']['default'] = [
  'database' => 'drupal_v',
  'username' => 'drupal',
  'password' => 'drupalpass',
  'host' => 'ff-drupal-db',
  'port' => 3306,
  'driver' => 'mysql',
  'namespace' => 'Drupal\\mysql\\Driver\\Database\\mysql',
  'implementation' => 'mysql',
  'prefix' => '',
  'collation' => 'utf8mb4_general_ci',
];
$hash_salt = 'ff1ab2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f50617283940a5b6c7d8e9f0a1b2c3d4e5f60';
$settings['config_sync_directory'] = '../config/sync';
$settings['update_free_access'] = FALSE;
$settings['container_yamls'][] = __DIR__ . '/services.yml';
$settings['entity_update_batch_size'] = 50000000;
$settings['trusted_host_patterns'] = ['^.+$'];
$databases['default']['default'] = array (
  'database' => 'drupal_v',
  'username' => 'drupal',
  'password' => 'drupalpass',
  'prefix' => '',
  'host' => 'ff-drupal-db',
  'port' => 3306,
  'isolation_level' => 'READ COMMITTED',
  'driver' => 'mysql',
  'namespace' => 'Drupal\\mysql\\Driver\\Database\\mysql',
  'autoload' => 'core/modules/mysql/src/Driver/Database/mysql/',
);
$settings['hash_salt'] = '9Wc7Jdpp8Ew6_susBvA-sD-S_F8WUR971VBrE-nzQAbBw_TIZmN7Ny4t3mLl-HaWDA04PuvS2g';
