//go:build integration

package service_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// defaultSub is one alert_subscriptions row of a tenant, read as the superuser.
type defaultSub struct {
	UserID   uuid.UUID
	AllDevs  bool
	Severity string
	Channel  string
	Follows  bool
}

func tenantSubs(t *testing.T, env *servicetest.Env, tenant string) []defaultSub {
	t.Helper()
	rows, err := env.Super.Query(context.Background(), `
		SELECT s.user_id, s.device_pk IS NULL, s.min_severity, s.channel, coalesce(c.follows_account, false)
		  FROM alert_subscriptions s JOIN users u ON u.id = s.user_id
		  LEFT JOIN notification_channels c ON c.id = s.channel_id
		 WHERE u.tenant_id = $1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []defaultSub
	for rows.Next() {
		var s defaultSub
		if err := rows.Scan(&s.UserID, &s.AllDevs, &s.Severity, &s.Channel, &s.Follows); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// wantOneDefault fails unless the tenant holds exactly the default subscription for want.
func wantOneDefault(t *testing.T, env *servicetest.Env, tenant string, want uuid.UUID) {
	t.Helper()
	subs := tenantSubs(t, env, tenant)
	if len(subs) != 1 {
		t.Fatalf("%s has %d subscriptions, want 1: %+v", tenant, len(subs), subs)
	}
	s := subs[0]
	if s.UserID != want || !s.AllDevs || s.Severity != service.DefaultSubscriptionSeverity || s.Channel != "email" || !s.Follows {
		t.Fatalf("subscription = %+v, want user %v, all devices, warn, account email", s, want)
	}
}

func TestDefaultSubscriptionOnPairing(t *testing.T) {
	env := servicetest.Start(t)
	certs := env.Services.Certificates
	dev := env.Services.Devices
	auth := env.Services.Auth
	ctx := context.Background()
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	const pem = "pem"

	t.Run("issue_subscribes_the_tenant_admin_once", func(t *testing.T) {
		const tn = "dsub-issue"
		env.SeedTenant(t, tn)
		mustCreateUser(t, auth, tn, "plain@dsub.test")
		admin, err := auth.CreateUser(tn, "admin@dsub.test", "", true)
		if err != nil {
			t.Fatal(err)
		}
		pk := mustUpsert(t, dev, tn, "dsub-dev-1", "", "", "", "")
		if err := certs.Issue(ctx, tn, pk, "dsub-s1", "dsub-cn1", nb, na, pem); err != nil {
			t.Fatal(err)
		}
		wantOneDefault(t, env, tn, admin.ID)
		// Re-pair and a second device never add another.
		if err := certs.Issue(ctx, tn, pk, "dsub-s2", "dsub-cn2", nb, na, pem); err != nil {
			t.Fatal(err)
		}
		pk2 := mustUpsert(t, dev, tn, "dsub-dev-2", "", "", "", "")
		if err := certs.Issue(ctx, tn, pk2, "dsub-s3", "dsub-cn3", nb, na, pem); err != nil {
			t.Fatal(err)
		}
		wantOneDefault(t, env, tn, admin.ID)
	})

	t.Run("rule_on_an_unpaired_device_does_not_block_the_default", func(t *testing.T) {
		const tn = "dsub-unpaired"
		env.SeedTenant(t, tn)
		u := mustCreateUser(t, auth, tn, "only@unpaired.test")
		other := mustUpsert(t, dev, tn, "dsub-unp-other", "", "", "", "")
		ch, err := env.Services.Alerts.CreateChannel(ctx, tn, u.ID, "telegram", "98", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Services.Alerts.CreateChannelSubscription(ctx, tn, u.ID, &other, ch, "warn"); err != nil {
			t.Fatal(err)
		}
		pk := mustUpsert(t, dev, tn, "dsub-unp-1", "", "", "", "")
		if err := certs.Issue(ctx, tn, pk, "dsub-u1", "dsub-ucn1", nb, na, pem); err != nil {
			t.Fatal(err)
		}
		defaults := 0
		for _, s := range tenantSubs(t, env, tn) {
			if s.AllDevs && s.UserID == u.ID {
				defaults++
			}
		}
		if defaults != 1 {
			t.Fatalf("%d all-device subscriptions after pairing, want the default", defaults)
		}
	})

	t.Run("enrollment_issue_subscribes_the_claiming_user", func(t *testing.T) {
		const tn = "dsub-claim"
		env.SeedTenant(t, tn)
		if _, err := auth.CreateUser(tn, "admin@claim.test", "", true); err != nil {
			t.Fatal(err)
		}
		claimer := mustCreateUser(t, auth, tn, "claimer@claim.test")
		pk := mustUpsert(t, dev, tn, "dsub-claim-1", "", "", "", "")
		if _, err := env.Super.Exec(ctx, `UPDATE devices SET owner_user_id = $1 WHERE id = $2`, claimer.ID, pk); err != nil {
			t.Fatal(err)
		}
		if err := certs.IssueWithIdentity(ctx, tn, pk, "dsub-c1", "dsub-ccn1", nb, na, pem, strings.Repeat("ab", 32)); err != nil {
			t.Fatal(err)
		}
		wantOneDefault(t, env, tn, claimer.ID)
	})

	t.Run("admin_pair_activate_subscribes_and_pending_does_not", func(t *testing.T) {
		const tn = "dsub-activate"
		env.SeedTenant(t, tn)
		u := mustCreateUser(t, auth, tn, "only@act.test")
		pk := mustUpsert(t, dev, tn, "dsub-act-1", "", "", "", "")
		id, err := certs.IssuePending(ctx, tn, pk, "dsub-a1", "dsub-acn1", nb, na, pem)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(tenantSubs(t, env, tn)); n != 0 {
			t.Fatalf("pending cert subscribed %d, want 0", n)
		}
		if err := certs.Activate(ctx, tn, id, pk); err != nil {
			t.Fatal(err)
		}
		wantOneDefault(t, env, tn, u.ID)
	})

	t.Run("existing_subscription_is_left_alone", func(t *testing.T) {
		const tn = "dsub-existing"
		env.SeedTenant(t, tn)
		admin, err := auth.CreateUser(tn, "admin@ex.test", "", true)
		if err != nil {
			t.Fatal(err)
		}
		other := mustCreateUser(t, auth, tn, "other@ex.test")
		ch, err := env.Services.Alerts.CreateChannel(ctx, tn, other.ID, "telegram", "4242", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Services.Alerts.CreateChannelSubscription(ctx, tn, other.ID, nil, ch, "crit"); err != nil {
			t.Fatal(err)
		}
		pk := mustUpsert(t, dev, tn, "dsub-ex-1", "", "", "", "")
		if err := certs.Issue(ctx, tn, pk, "dsub-e1", "dsub-ecn1", nb, na, pem); err != nil {
			t.Fatal(err)
		}
		subs := tenantSubs(t, env, tn)
		if len(subs) != 1 || subs[0].UserID == admin.ID {
			t.Fatalf("subscriptions = %+v, want only the existing one", subs)
		}
	})

	t.Run("tenant_without_users_still_pairs", func(t *testing.T) {
		const tn = "dsub-empty"
		env.SeedTenant(t, tn)
		pk := mustUpsert(t, dev, tn, "dsub-empty-1", "", "", "", "")
		if err := certs.Issue(ctx, tn, pk, "dsub-x1", "dsub-xcn1", nb, na, pem); err != nil {
			t.Fatalf("pairing failed: %v", err)
		}
		if d, _ := dev.GetByID(pk, tn); d == nil || d.PairedAt == nil {
			t.Fatal("device not paired")
		}
	})

	t.Run("parallel_pairings_subscribe_once", func(t *testing.T) {
		const tn = "dsub-race"
		env.SeedTenant(t, tn)
		u := mustCreateUser(t, auth, tn, "race@race.test")
		var wg sync.WaitGroup
		errs := make(chan error, 6)
		for i := range 6 {
			pk := mustUpsert(t, dev, tn, fmt.Sprintf("dsub-race-%d", i), "", "", "", "")
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- certs.Issue(ctx, tn, pk, fmt.Sprintf("dsub-r%d", i), fmt.Sprintf("dsub-rcn%d", i), nb, na, pem)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		wantOneDefault(t, env, tn, u.ID)
	})
}

func TestAlertCoverage(t *testing.T) {
	env := servicetest.Start(t)
	al := env.Services.Alerts
	ctx := context.Background()
	const tn, other = "cov-a", "cov-b"
	env.SeedTenant(t, tn)
	env.SeedTenant(t, other)
	u := mustCreateUser(t, env.Services.Auth, tn, "cov@a.test")
	mustCreateUser(t, env.Services.Auth, other, "cov@b.test")

	cover := func(tenant string) (bool, int) {
		t.Helper()
		p, n, err := al.AlertCoverage(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		return p, n
	}
	if p, n := cover(tn); p || n != 0 {
		t.Fatalf("empty tenant = %v, %d", p, n)
	}
	pk := mustUpsert(t, env.Services.Devices, tn, "cov-dev", "", "", "", "")
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, pk); err != nil {
		t.Fatal(err)
	}
	if p, n := cover(tn); !p || n != 0 {
		t.Fatalf("paired, no subscriber = %v, %d", p, n)
	}
	ch, err := al.CreateChannel(ctx, tn, u.ID, "telegram", "99", "")
	if err != nil {
		t.Fatal(err)
	}
	// A rule for an unpaired device reaches nobody for the paired one.
	unpaired := mustUpsert(t, env.Services.Devices, tn, "cov-dev-unpaired", "", "", "", "")
	if err := al.CreateChannelSubscription(ctx, tn, u.ID, &unpaired, ch, "warn"); err != nil {
		t.Fatal(err)
	}
	if _, n := cover(tn); n != 0 {
		t.Fatalf("subscription on an unpaired device counted, %d subscribers", n)
	}
	if n, _ := env.Services.Tenants.CountSubscribersAny(tn); n != 0 {
		t.Fatalf("CountSubscribersAny counts an unpaired-device rule, %d", n)
	}
	if err := al.CreateChannelSubscription(ctx, tn, u.ID, nil, ch, "warn"); err != nil {
		t.Fatal(err)
	}
	if p, n := cover(tn); !p || n != 1 {
		t.Fatalf("subscribed = %v, %d, want true, 1", p, n)
	}
	if n, err := env.Services.Tenants.CountSubscribersAny(tn); err != nil || n != 1 {
		t.Fatalf("CountSubscribersAny = %d, %v, want 1", n, err)
	}
	// A switched-off channel reaches nobody.
	if err := al.SetChannelEnabled(ctx, tn, u.ID, ch, false); err != nil {
		t.Fatal(err)
	}
	if _, n := cover(tn); n != 0 {
		t.Fatalf("disabled channel counted, %d subscribers", n)
	}
	if n, _ := env.Services.Tenants.CountSubscribersAny(tn); n != 0 {
		t.Fatalf("CountSubscribersAny with disabled channel = %d", n)
	}
	if p, n := cover(other); p || n != 0 {
		t.Fatalf("other tenant = %v, %d", p, n)
	}
}
