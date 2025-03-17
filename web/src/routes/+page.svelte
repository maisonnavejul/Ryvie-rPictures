<script lang="ts">
  import { AppRoute } from '$lib/constants';
  import { Heading, Button } from '@immich/ui';
  import { t } from 'svelte-i18n';
</script>

<div class="flex h-screen flex-col place-content-center place-items-center">
  <div class="flex max-w-[350px] flex-col place-items-center gap-10 text-center">
    <div class="flex place-content-center place-items-center">
      <img src="/rPictures.png" alt="rPictures Logo" class="h-32" />
    </div>
    <Heading size="giant" color="primary" tag="h1">{$t('welcome_to_immich')}</Heading>
    <Button href={AppRoute.AUTH_REGISTER} size="giant" shape="round">
      {$t('landing.get_started')}
    </Button>
  </div>
</div>
