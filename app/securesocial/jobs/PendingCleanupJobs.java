/**
 * Copyright 2011 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss 
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
 *
 *
 */
package securesocial.jobs;

import play.jobs.Every;
import play.jobs.Job;
import securesocial.provider.UserService;

/**
 * A Job that deletes pending activations, password reset requests 
 * Used to be @Every("24h")
 *	Instead this now gets scheduled from the SecureSocialPlugin according to the configured value "securesocial.resetjobs.timer".
 *	If that is not configured, the default of 24h is used
 */
public class PendingCleanupJobs extends Job
{
    @Override
    public void doJob() throws Exception {
        UserService.deletePendingActivations();
        UserService.deletePendingPasswordResets();
    }
}
