<script lang="ts">
  import { Theme } from '$lib/constants';
  import { colorTheme } from '$lib/stores/preferences.store';
  import { DateTime } from 'luxon';
  import { t } from 'svelte-i18n';
  import type { HTMLImgAttributes } from 'svelte/elements';

  interface Props extends HTMLImgAttributes {
    noText?: boolean;
    draggable?: boolean;
  }

  let { noText = false, draggable = false, ...rest }: Props = $props();

  const logoUrl = $derived('/rPictures.svg');

  const today = DateTime.now().toLocal();
</script>

{#if today.month === 4 && today.day === 1}
  <img src="/rPictures.svg" alt="rPictures logo" class="h-14" {draggable} />
{:else}
  <img src={logoUrl} alt="rPictures logo" {draggable} {...rest} />
{/if}
