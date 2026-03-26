/*
 * Copyright 2025 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { useParams } from 'react-router-dom';

import {
  Alert,
  Box,
  Button,
  Card,
  CardBody,
  CardFooter,
  Container,
  Flex,
  FullPage,
  Text,
  VisuallyHidden,
} from '@backstage/ui';
import {
  RiLinkM,
  RiCheckboxCircleLine,
  RiCloseCircleLine,
} from '@remixicon/react';
import { useProviderConnectSession } from './useProviderConnectSession';
import styles from './ProviderConnectPage.module.css';

const ProviderConnectPageLayout = ({
  children,
}: {
  children: React.ReactNode;
}) => (
  <FullPage>
    <VisuallyHidden>
      <h1>Connect Provider</h1>
    </VisuallyHidden>
    <Container py="8">{children}</Container>
  </FullPage>
);

export const ProviderConnectPage = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { state, handleAction } = useProviderConnectSession({ sessionId });

  if (!sessionId) {
    return (
      <ProviderConnectPageLayout>
        <Alert
          status="info"
          icon
          title="Invalid Request"
          description="The session ID is missing or invalid."
        />
      </ProviderConnectPageLayout>
    );
  }

  if (state.status === 'loading') {
    return (
      <ProviderConnectPageLayout>
        <Alert loading title="Loading provider connection request..." />
      </ProviderConnectPageLayout>
    );
  }

  if (state.status === 'error') {
    return (
      <ProviderConnectPageLayout>
        <Alert
          status="danger"
          icon
          title="Connection Error"
          description={state.error}
        />
      </ProviderConnectPageLayout>
    );
  }

  if (state.status === 'completed') {
    return (
      <ProviderConnectPageLayout>
        <Card className={styles.card}>
          <CardBody>
            <Flex
              direction="column"
              align="center"
              gap="2"
              style={{ textAlign: 'center' }}
            >
              {state.action === 'approve' ? (
                <RiCheckboxCircleLine
                  size={64}
                  className={styles.completedIconSuccess}
                />
              ) : (
                <RiCloseCircleLine
                  size={64}
                  className={styles.completedIconDanger}
                />
              )}
              <Text as="h2" variant="title-small">
                {state.action === 'approve'
                  ? 'Provider Connected'
                  : 'Connection Denied'}
              </Text>
              <Text variant="body-medium" color="secondary">
                {state.action === 'approve'
                  ? 'The provider has been connected. You can close this tab and return to your application.'
                  : 'You have denied the provider connection request.'}
              </Text>
            </Flex>
          </CardBody>
        </Card>
      </ProviderConnectPageLayout>
    );
  }

  const session = state.session;
  const isSubmitting = state.status === 'submitting';
  const pluginName = session.clientName ?? session.clientId;
  const providerDescription = session.scope ?? 'a provider';

  return (
    <ProviderConnectPageLayout>
      <Card className={styles.card}>
        <CardBody>
          <Flex direction="column" gap="4">
            <Box className={styles.appHeader}>
              <RiLinkM size={40} className={styles.appIcon} />
              <Flex direction="column" gap="0.5">
                <Text as="span" variant="title-small" weight="bold">
                  {pluginName}
                </Text>
                <Text variant="body-small" color="secondary">
                  wants to connect to a provider on your behalf
                </Text>
              </Flex>
            </Box>

            <hr className={styles.divider} />

            <Alert
              status="info"
              icon
              title="Provider Access"
              description={`${providerDescription}. This will allow ${pluginName} to make requests using your provider credentials.`}
            />

            <Alert
              status="warning"
              icon
              title="Security Notice"
              description={
                <>
                  By authorizing, you are granting <strong>{pluginName}</strong>{' '}
                  access to your provider account. Only authorize plugins you
                  trust.
                  <div className={styles.callbackUrl}>
                    {session.redirectUri}
                  </div>
                </>
              }
            />
          </Flex>
        </CardBody>

        <CardFooter>
          <Flex justify="between" gap="4">
            <Button
              variant="secondary"
              isDisabled={isSubmitting}
              onPress={() => handleAction('reject')}
              iconStart={<RiCloseCircleLine />}
            >
              Deny
            </Button>
            <Button
              variant="primary"
              isDisabled={isSubmitting}
              onPress={() => handleAction('approve')}
              iconStart={<RiCheckboxCircleLine />}
            >
              {isSubmitting ? 'Connecting...' : 'Authorize'}
            </Button>
          </Flex>
        </CardFooter>
      </Card>
    </ProviderConnectPageLayout>
  );
};
