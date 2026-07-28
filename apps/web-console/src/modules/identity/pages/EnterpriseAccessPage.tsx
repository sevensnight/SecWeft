import { useQuery } from '@tanstack/react-query';
import {
  Alert,
  Card,
  Col,
  Descriptions,
  Empty,
  List,
  Row,
  Select,
  Space,
  Statistic,
  Tag,
  Typography,
} from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnBoolean, cnLabel } from '../../../i18n/formatters';
import { useSessionStore } from '../../../stores/session';
import {
  enterpriseAuditQuery,
  enterpriseRolesQuery,
  enterpriseSessionQuery,
  enterpriseUsersQuery,
  projectsQuery,
  tenantQuery,
} from '../api/queries';

function hasPermission(
  tenantPermissions: string[],
  projectPermissions: string[],
  permission: string,
) {
  return tenantPermissions.includes(permission) || projectPermissions.includes(permission);
}

export function EnterpriseAccessPage() {
  const selectedProjectId = useSessionStore((state) => state.projectId);
  const setProjectId = useSessionStore((state) => state.setProjectId);
  const session = useQuery(enterpriseSessionQuery());
  const tenantPermissions = session.data?.permissions ?? [];
  const selectedProject = session.data?.projects.find(
    (project) => project.project_id === selectedProjectId,
  );
  const projectPermissions = selectedProject?.permissions ?? [];
  const canReadTenant = tenantPermissions.includes('tenant.read');
  const canReadProjects = hasPermission(tenantPermissions, projectPermissions, 'project.read')
    || (session.data?.projects.some((project) => project.permissions.includes('project.read')) ?? false);
  const canReadUsers = tenantPermissions.includes('membership.read');
  const canReadRoles = tenantPermissions.includes('role.read');
  const canReadAudit = hasPermission(tenantPermissions, projectPermissions, 'audit.read');

  const tenant = useQuery({ ...tenantQuery(), enabled: canReadTenant });
  const projects = useQuery({ ...projectsQuery(), enabled: canReadProjects });
  const users = useQuery({ ...enterpriseUsersQuery(), enabled: canReadUsers });
  const roles = useQuery({ ...enterpriseRolesQuery(), enabled: canReadRoles });
  const audit = useQuery({ ...enterpriseAuditQuery(), enabled: canReadAudit });
  const effectivePermissionCount = new Set([
    ...tenantPermissions,
    ...projectPermissions,
  ]).size;

  if (session.isPending) return <LoadingState label="正在解析服务端权限…" />;
  if (session.isError) {
    return <QueryErrorState error={session.error} onRetry={() => void session.refetch()} />;
  }

  const refreshScope = (projectId: string | null) => {
    setProjectId(projectId);
    void queryClient.invalidateQueries({ queryKey: ['enterprise'] });
  };

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>身份、租户与权限</Typography.Title>
        <Typography.Text type="secondary">
          权限和数据范围由服务端会话返回；前端只做界面裁剪，后端仍会再次校验。
        </Typography.Text>
      </div>

      <Select
        aria-label="当前项目"
        allowClear
        placeholder="选择项目上下文"
        value={selectedProjectId ?? undefined}
        loading={projects.isLoading}
        options={(projects.data ?? []).map((project) => ({
          value: project.id,
          label: project.display_name,
        }))}
        onChange={(value) => refreshScope(value ?? null)}
        className="project-selector"
      />

      <Alert
        showIcon
        type="success"
        message="OIDC + 数据范围 RBAC 已生效"
        description="浏览器令牌只保存在内存；租户和项目权限由 API 端继续强制执行。"
        className="section-gap"
      />

      <Row gutter={[16, 16]} className="section-gap">
        <Col xs={24} md={8}>
          <Card><Statistic title="租户角色" value={session.data.roles.length} /></Card>
        </Col>
        <Col xs={24} md={8}>
          <Card><Statistic title="有效权限" value={effectivePermissionCount} /></Card>
        </Col>
        <Col xs={24} md={8}>
          <Card><Statistic title="可见项目" value={session.data.projects.length} /></Card>
        </Col>
      </Row>

      <Card title="当前会话" className="section-gap">
        <Descriptions column={{ xs: 1, md: 2 }}>
          <Descriptions.Item label="用户名">{session.data.username}</Descriptions.Item>
          <Descriptions.Item label="租户状态">
            <Tag color="green">{cnLabel(session.data.tenant_status)}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="用户 ID">{session.data.user_id}</Descriptions.Item>
          <Descriptions.Item label="租户 ID">{session.data.tenant_id}</Descriptions.Item>
        </Descriptions>
        <Space wrap>
          {session.data.roles.map((role) => <Tag key={role} color="blue">{role}</Tag>)}
          {selectedProject?.roles.map((role) => <Tag key={role} color="cyan">{role}</Tag>)}
        </Space>
      </Card>

      {canReadTenant ? (
        <Card title="租户" className="section-gap" loading={tenant.isLoading}>
          {tenant.data ? (
            <Descriptions column={{ xs: 1, md: 3 }}>
              <Descriptions.Item label="名称">{tenant.data.display_name}</Descriptions.Item>
              <Descriptions.Item label="标识">{tenant.data.slug}</Descriptions.Item>
              <Descriptions.Item label="版本">{tenant.data.version}</Descriptions.Item>
            </Descriptions>
          ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
        </Card>
      ) : null}

      {canReadUsers ? (
        <Card title="租户成员" className="section-gap" loading={users.isLoading}>
          <List
            dataSource={users.data ?? []}
            locale={{ emptyText: '暂无成员' }}
            renderItem={(user) => (
              <List.Item extra={<Tag color={user.active ? 'green' : 'default'}>{cnBoolean(user.active)}</Tag>}>
                <List.Item.Meta title={user.username} description={user.email ?? user.subject} />
              </List.Item>
            )}
          />
        </Card>
      ) : null}

      {canReadRoles ? (
        <Card title="角色与显式权限" className="section-gap" loading={roles.isLoading}>
          <List
            dataSource={roles.data ?? []}
            locale={{ emptyText: '暂无角色' }}
            renderItem={(role) => (
              <List.Item>
                <List.Item.Meta
                  title={<Space><Typography.Text strong>{role.code}</Typography.Text><Tag>{cnLabel(role.scope_type)}</Tag></Space>}
                  description={`${role.description} · ${role.permissions.length} 项权限`}
                />
              </List.Item>
            )}
          />
        </Card>
      ) : null}

      {canReadAudit ? (
        <Card title="最近审计事件" className="section-gap" loading={audit.isLoading}>
          <List
            dataSource={(audit.data ?? []).slice(0, 20)}
            locale={{ emptyText: '暂无审计事件' }}
            renderItem={(event) => (
              <List.Item extra={<Tag>{cnLabel(event.outcome)}</Tag>}>
                <List.Item.Meta
                  title={event.action}
                  description={`${event.resource_type}:${event.resource_id} · ${new Date(event.occurred_at).toLocaleString()}`}
                />
              </List.Item>
            )}
          />
        </Card>
      ) : null}
    </section>
  );
}
